#!/usr/bin/python3
"""Guest-only catalog synchronization. Explicit roots must be inside its Safe."""

import argparse
import json
import os
from pathlib import Path
import resource
import signal
import sqlite3
import subprocess
import sys
import time
import zlib

from oblivion_history.catalog import Catalog
from oblivion_history.admin import catalog_state
from oblivion_history.layout import Layout
from oblivion_history.deletion import delete_chat
from oblivion_history.sync import active_agent, sync
from oblivion_history.rpc import request, call, serve, admin_request


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=("sync", "watch", "hold", "list", "delete", "author", "author-hook", "author-child")
    )
    parser.add_argument("--home")
    parser.add_argument("--workspace")
    parser.add_argument("--state")
    parser.add_argument("--data-home")
    parser.add_argument("--config-home")
    parser.add_argument("--cache-home")
    parser.add_argument("--native-state-home")
    parser.add_argument("--codex-home")
    parser.add_argument("--claude-home")
    parser.add_argument("--sync-socket")
    parser.add_argument("--admin-socket")
    parser.add_argument("--author-socket")
    parser.add_argument("--gate", type=int)
    parser.add_argument("--chat")
    parser.add_argument("--confirm")
    parser.add_argument("--group-signals", action="store_true")
    parser.add_argument("--agent", choices=("codex", "claude", "opencode2"))
    parser.add_argument("--interval", type=float, default=2)
    values = sys.argv[1:]
    boundary = values.index("--") if "--" in values else len(values)
    command = values[boundary + 1 :]
    args = parser.parse_args(values[:boundary])
    if args.operation == "author-child":
        from oblivion_history.author import child

        if args.gate is None or not command:
            parser.error("author-child requires a gate and command")
        return child(command, args.gate)
    if args.operation == "author-hook":
        from oblivion_history.author import hook

        if not args.author_socket:
            parser.error("author-hook requires --author-socket")
        return hook(args.author_socket)
    admin_message = None
    if args.operation in ("list", "delete"):
        admin_message = {"version": 1, "operation": args.operation}
        if args.operation == "delete":
            admin_message.update(chat_id=args.chat, confirm=args.confirm)
        admin_request(admin_message)
        if args.admin_socket:
            result = call(args.admin_socket, admin_message)["result"]
            print(json.dumps(result, sort_keys=True))
            return 1 if result.get("error") or result.get("errors") else 0
    if args.operation == "sync" and args.sync_socket:
        report = request(args.sync_socket)
        print(json.dumps(report, sort_keys=True))
        return 1 if report["errors"] else 0
    if not args.home or not args.workspace or not args.state:
        parser.error("home, workspace and state are required")
    if args.operation == "author":
        from oblivion_history.author import serve

        if not args.author_socket:
            parser.error("author requires --author-socket")
        serve(args.author_socket, args.state, args.workspace)
        return 0
    layout = Layout.resolve(
        args.home,
        data=args.data_home,
        config=args.config_home,
        cache=args.cache_home,
        state=args.native_state_home,
        codex=args.codex_home,
        claude=args.claude_home,
    )

    def reconcile():
        try:
            report = sync(args.home, args.workspace, args.state, layout=layout)
            catalog = Catalog(args.state)
            report["pending"] = sorted(catalog.pending())
            catalog.close()
            return report
        except (sqlite3.Error, zlib.error, ValueError) as error:
            # Keep the RPC alive so storage failures are inspectable. Never
            # reset the catalog or launch against an unreconciled projection.
            return {
                "ingested": 0,
                "projected": 0,
                "busy": [],
                "retained": [],
                "errors": [
                    {
                        "error": "unsupported_catalog_format"
                        if str(error) == "unsupported_catalog_format"
                        else "history_catalog_unavailable"
                    }
                ],
                "pending": ["codex", "claude", "opencode2"],
            }

    def administer(message):
        try:
            if message["operation"] == "catalog-state":
                return catalog_state(args.state, message["cursor"])
            if message["operation"] == "delete":
                return delete_chat(
                    layout,
                    args.workspace,
                    args.state,
                    message["chat_id"],
                    message["confirm"],
                )
            catalog = Catalog(args.state)
            try:
                with catalog.exclusive():
                    rows = [
                        dict(row)
                        for row in catalog.db.execute(
                            "SELECT id AS chat_id,substr(title,1,240) AS title,updated FROM chat WHERE id NOT IN (SELECT chat_id FROM deleted_chat) ORDER BY updated DESC,id LIMIT 201"
                        )
                    ]
                    return {"chats": rows[:200], "truncated": len(rows) > 200}
            finally:
                catalog.close()
        except ValueError as error:
            return {
                "error": str(error)
                if str(error)
                in (
                    "history_delete_busy",
                    "history_chat_not_found",
                    "history_delete_confirmation_mismatch",
                )
                else "history_operation_failed"
            }
        except (OSError, sqlite3.Error, subprocess.SubprocessError):
            return {"error": "history_operation_failed"}

    if admin_message:
        result = administer(admin_message)
        print(json.dumps(result, sort_keys=True))
        return 1 if result.get("error") or result.get("errors") else 0

    if args.operation == "watch" and args.sync_socket:
        if args.interval < 0.25:
            parser.error("interval must be at least 0.25 seconds")
        serve(
            args.sync_socket,
            reconcile,
            args.interval,
            admin_path=args.admin_socket,
            admin=administer,
        )
        return 0
    if args.operation == "hold":
        if not args.agent or not command:
            parser.error("hold requires --agent and a command")
        report = request(args.sync_socket) if args.sync_socket else reconcile()
        report_retention(report, args.agent)
        pending = report["pending"]
        if args.agent in pending:
            print("history_recovery_required", file=sys.stderr)
            return 1
        with active_agent(args.state, args.agent):
            environment = os.environ.copy()
            environment.update(layout.environment())
            if args.agent == "claude" and args.author_socket:
                from oblivion_history.author import call

                owner = call(args.author_socket, {"version": 1, "operation": "register", "agent": args.agent})["owner"]
                environment["OBLIVION_AUTHOR_OWNER"] = owner
                gate, release = os.pipe()
                try:
                    process = subprocess.Popen(
                        [sys.executable, "-B", str(Path(__file__).resolve()), "author-child", "--gate", str(gate), "--", *command],
                        env=environment, pass_fds=(gate,),
                    )
                    try:
                        call(args.author_socket, {"version": 1, "operation": "bind-child", "owner": owner, "pid": process.pid})
                        os.write(release, b"1")
                    except BaseException:
                        process.kill()
                        process.wait()
                        raise
                finally:
                    os.close(gate)
                    os.close(release)
            else:
                process = subprocess.Popen(command, env=environment)

            def forward(number, _):
                if args.group_signals:
                    return
                try:
                    process.send_signal(number)
                except ProcessLookupError:
                    pass

            for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(number, forward)
            status = process.wait()
        try:
            report_retention(
                request(args.sync_socket) if args.sync_socket else reconcile(),
                args.agent,
            )
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
            print("history_sync_incomplete", file=sys.stderr)
        return status if status >= 0 else 128 - status
    if args.interval < 0.25:
        parser.error("interval must be at least 0.25 seconds")
    while True:
        report = reconcile()
        if args.operation == "sync":
            # Identifiers and counts only. Native payloads stay in the Safe.
            print(json.dumps(report, sort_keys=True))
            return 1 if report["errors"] else 0
        time.sleep(args.interval)


def report_retention(report, agent):
    retained = [
        row
        for row in report["retained"]
        if row["target"] == agent and row["storage"] == "encrypted_archive"
    ]
    if retained:
        kinds = ", ".join(sorted({row["kind"] for row in retained}))
        print(
            "History sync retained native data in the encrypted archive for "
            + agent
            + ". Portable history omits "
            + kinds
            + ".",
            file=sys.stderr,
        )
    if report["errors"]:
        print("history_sync_incomplete", file=sys.stderr)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("history_sync_cancelled", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        print("history_sync_failed", file=sys.stderr)
        sys.exit(1)
