#!/usr/bin/env python3
"""Local file chooser/CLI adapter for an authorized copy stream on FD 3.

The Rust copy engine owns selection, manifests, paths, digests and publication.
This adapter never extracts archives or opens a Safe filesystem on the host.
"""
import argparse
import os
from pathlib import Path
import secrets
import sys


def main():
    parser = argparse.ArgumentParser(description='Copy selected files over a private Oblivion stream on FD 3.')
    parser.add_argument('--copy-binary', default='oblivion-copy')
    parser.add_argument('--timeout', type=int, default=3600, help='Maximum transfer duration in seconds')
    operations = parser.add_subparsers(dest='operation', required=True)
    send = operations.add_parser('send', help='Send one explicit local file or directory')
    send.add_argument('source', type=Path)
    send.add_argument('--id', default=None)
    receive = operations.add_parser('receive', help='Receive one tree under a new name')
    receive.add_argument('--inbox', type=Path, required=True)
    receive.add_argument('destination', type=Path)
    receive.add_argument('name')
    download = operations.add_parser('download', help='Request one file or directory from a Safe')
    download.add_argument('selection', help='Path relative to the authorized guest source root')
    download.add_argument('--inbox', type=Path, required=True)
    download.add_argument('destination', type=Path)
    download.add_argument('name')
    download.add_argument('--id', default=None)
    recover = operations.add_parser('recover', help='Finish publishing a verified private copy')
    recover.add_argument('--inbox', type=Path, required=True)
    recover.add_argument('destination', type=Path)
    recover.add_argument('id')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error('timeout must be between 1 and 3600 seconds')
    budget = str(args.timeout * 1000)
    if args.operation == 'send':
        command = ['stream-send', str(args.source.absolute()), args.id or secrets.token_hex(16), budget]
    elif args.operation == 'receive':
        command = ['stream-receive', str(args.inbox.absolute()), str(args.destination.absolute()), args.name, budget]
    elif args.operation == 'download':
        command = ['stream-download', args.selection, str(args.inbox.absolute()),
                   str(args.destination.absolute()), args.name, args.id or secrets.token_hex(16), budget]
    else:
        command = ['stream-recover', str(args.inbox.absolute()), str(args.destination.absolute()), args.id]
    if args.operation != 'recover':
        os.set_inheritable(3, True)
    os.execvp(args.copy_binary, [args.copy_binary, *command])


if __name__ == '__main__':
    try:
        main()
    except OSError:
        print('file_stream_unavailable', file=sys.stderr)
        sys.exit(1)
