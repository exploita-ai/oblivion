"""Real process/signal regression; does not qualify systemd or native chat I/O."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform == "linux", "Linux process/session lifecycle")
class Cleanup(unittest.TestCase):
    def test_term_revokes_client_process_group_but_not_its_detached_server(self):
        source = str(Path(__file__).parents[1] / "guest/agent-channel.py")
        child = """
import json,os,subprocess,sys,time
daemon=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(json.dumps({'root':os.getpid(),'daemon':daemon.pid}),flush=True)
time.sleep(60)
"""
        owner = """
import importlib.util,signal,subprocess,sys,time
spec=importlib.util.spec_from_file_location('channel',sys.argv[1])
channel=importlib.util.module_from_spec(spec);spec.loader.exec_module(channel)
signal.signal(signal.SIGTERM,channel.stop_channel)
signal.signal(signal.SIGHUP,channel.stop_channel)
try:
    with channel.owned_process([sys.executable,'-c',sys.argv[2]],start_new_session=True,stdout=subprocess.PIPE,stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL) as process:
        print(process.stdout.readline().decode().strip(),flush=True)
        time.sleep(60)
except ConnectionAbortedError:
    pass
"""
        process = subprocess.Popen([sys.executable, "-B", "-c", owner, source, child],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children = None
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], "child readiness timeout")
            children = json.loads(process.stdout.readline(4096))
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertEqual(process.stderr.read(), b"")
            self.assertFalse(Path(f"/proc/{children['root']}").exists(), "client root was not reaped")
            daemon = Path(f"/proc/{children['daemon']}/stat").read_text()
            self.assertNotEqual(daemon.rsplit(") ", 1)[1].split()[0], "Z", "detached native-style server was stopped")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if children is not None:
                for pid in children.values():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.waitpid(children["daemon"], 0)
                except ChildProcessError:
                    pass
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
