"""Real files, leases and process supervision; native event records are synthetic."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import select
import sys
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location("managed_job", Path(__file__).parents[1] / "guest/managed-job.py")
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)


def record(state="queued"):
    return {"version": 1, "info": {"job_id": "a"*32, "request_id": "b"*32, "agent": "codex", "state": state,
            "native_chat_id": None, "reason": None}, "output_bytes": 0}


class Managed(unittest.TestCase):
    def setUp(self):
        job.CANCELLED.clear()
        self.fixture = tempfile.TemporaryDirectory(prefix="oblivion-jobs-")
        self.vault = Path(self.fixture.name)
        for folder in ("home", "workspace"):
            (self.vault/folder).mkdir(mode=0o700)
        self.directory = job.root(self.vault)

    def tearDown(self):
        os.close(self.directory)
        self.fixture.cleanup()

    def target(self):
        os.mkdir("a"*32, mode=0o700, dir_fd=self.directory)
        return os.open("a"*32, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=self.directory)

    def test_fragmented_bounded_events_never_invent_ids(self):
        events = job.Events("codex")
        payload = json.dumps({"type":"thread.started", "thread_id":"12345678-1234-4234-8234-123456789abc"}).encode()+b"\n"
        for byte in payload:
            events.feed("stdout", bytes([byte]))
        self.assertEqual(events.native, "12345678-1234-4234-8234-123456789abc")
        events.feed("stdout", b'{"type":"turn.failed","error":{"code":"invalid_api_key"}}\n')
        self.assertEqual(events.reason, "needs-auth")
        missing = job.Events("claude")
        missing.feed("stdout", b'{"type":"assistant","session_id":"forged"}\n')
        self.assertIsNone(missing.native)
        missing.feed("stdout", b"x"*(1024*1024))
        self.assertLessEqual(len(missing.buffer), 65536)
        denied = job.Events("claude")
        denied.feed("stdout", b'{"type":"result","subtype":"success","permission_denials":[{"tool_name":"Bash"}]}\n')
        self.assertEqual(denied.reason, "needs-input")

    def test_completed_request_is_idempotent_without_executing_task(self):
        target = self.target()
        try:
            first = record("completed")
            job.write(target, first)
            result = job.execute(self.directory, "a"*32, "claude", "c"*32, b"different task", vault=self.vault)
            self.assertEqual(result, first["info"])
            self.assertFalse((self.vault/"home/.oblivion-jobs"/("a"*32)/"task.txt").exists())
        finally:
            os.close(target)

    def test_live_lease_prevents_second_job_and_stale_run_becomes_interrupted(self):
        target = self.target()
        active = job.lease(self.directory)
        try:
            job.write(target, record("running"))
            fcntl.flock(active, fcntl.LOCK_EX|fcntl.LOCK_NB)
            os.write(active, b"a"*32)
            self.assertEqual(job.inspect(self.directory, "a"*32)["state"], "running")
            with self.assertRaises(job.Rejected) as rejected:
                job.execute(self.directory, "c"*32, "codex", "d"*32, b"task", vault=self.vault)
            self.assertEqual(rejected.exception.code, "busy")
            fcntl.flock(active, fcntl.LOCK_UN)
            result = job.inspect(self.directory, "a"*32)
            self.assertEqual((result["state"],result["reason"]), ("failed","interrupted"))
        finally:
            os.close(active)
            os.close(target)

    def supervise(self, script, deadline=2, cancel=False):
        target = self.target()
        value = record()
        stdout = os.open("stdout.jsonl", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600, dir_fd=target)
        stderr = os.open("stderr.txt", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600, dir_fd=target)
        process = subprocess.Popen([sys.executable,"-B","-u","-c",script], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        timer = threading.Timer(0.15,job.CANCELLED.set) if cancel else None
        try:
            if timer:
                timer.start()
            with contextlib.redirect_stdout(io.StringIO()):
                job.supervise(process,target,value,stdout,stderr,deadline_seconds=deadline)
            return value,process.returncode
        finally:
            if timer:
                timer.join()
            job.stop(process)
            process.stdout.close()
            process.stderr.close()
            os.close(stdout)
            os.close(stderr)
            os.close(target)

    def test_exit_zero_is_insufficient_without_native_completion(self):
        value,code = self.supervise("print('nothing structured')")
        self.assertEqual(code,0)
        self.assertEqual((value["info"]["state"],value["info"]["reason"]),("failed","agent-exit"))

    def test_supervisor_saves_output_and_recognizes_completion(self):
        script = "import json; print(json.dumps({'type':'thread.started','thread_id':'12345678-1234-4234-8234-123456789abc'})); print(json.dumps({'type':'turn.completed'}))"
        value,code = self.supervise(script)
        self.assertEqual((value["info"]["state"],code),("completed",0))
        self.assertTrue(value["info"]["native_chat_id"])
        self.assertGreater(value["output_bytes"],0)

    def test_real_child_output_quota(self):
        value,_ = self.supervise("import os; os.write(1,b'x'*(5*1024*1024))",deadline=5)
        self.assertEqual((value["info"]["state"],value["info"]["reason"]),("failed","output-limit"))
        self.assertEqual(value["output_bytes"],job.OUTPUT_LIMIT)

    def test_real_process_timeout(self):
        value,code = self.supervise("import time; time.sleep(60)",deadline=0.2)
        self.assertEqual((value["info"]["state"],value["info"]["reason"]),("failed","timeout"))
        self.assertLess(code,0)

    def test_real_process_cancellation(self):
        value,code = self.supervise("import time; time.sleep(60)",cancel=True)
        self.assertEqual(value["info"]["state"],"cancelled")
        self.assertLess(code,0)

    def test_stop_kills_descendants_even_when_leader_exits_first(self):
        child = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(60)"
        parent = "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-u','-c'," + repr(child) + "]); time.sleep(60)"
        process = subprocess.Popen([sys.executable,"-B","-u","-c",parent],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
        try:
            self.assertEqual(process.stdout.readline(),b"ready\n")
            job.stop(process)
            self.assertTrue(select.select([process.stdout],[],[],2)[0])
            self.assertEqual(process.stdout.read(1),b"")
        finally:
            job.stop(process)
            process.stdout.close()

    def test_future_manifest_is_not_replaced(self):
        target = self.target()
        try:
            future = record()
            future["version"] = 2
            path = self.vault/"home/.oblivion-jobs"/("a"*32)/"status.json"
            path.write_text(json.dumps(future))
            path.chmod(0o600)
            with self.assertRaises(job.Rejected):
                job.inspect(self.directory,"a"*32)
            self.assertEqual(json.loads(path.read_text())["version"],2)
            path.unlink()
            path.symlink_to(self.vault/"workspace/other")
            with self.assertRaises(OSError):
                job.inspect(self.directory,"a"*32)
        finally:
            os.close(target)


if __name__ == "__main__":
    unittest.main()
