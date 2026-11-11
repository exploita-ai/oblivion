import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and shutil.which("setpriv"), "requires Linux root fixture with setpriv")
class KeymapAcknowledgementPermissions(unittest.TestCase):
    def test_display_can_write_public_ack_and_capability_free_root_can_read_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            private = root / "oblivion-display"
            private.mkdir(mode=0o700)
            os.chown(private, 1104, 1104)
            hidden = private / "keymap-applied"
            hidden.write_text("42\n")
            hidden.chmod(0o600)
            os.chown(hidden, 1104, 1104)
            public = root / "oblivion-keymap-applied"
            public.touch(mode=0o644)
            os.chown(public, 1104, 1104)
            # The display UID can update the precreated file but cannot replace
            # its directory entry in a root-controlled /run equivalent.
            writer = subprocess.run(["setpriv", "--reuid=1104", "--regid=1104", "--clear-groups", sys.executable, "-I", "-c", '''
import pathlib,sys
path=pathlib.Path(sys.argv[1])
path.write_text("84\\n")
try: path.unlink()
except PermissionError: pass
else: raise AssertionError("display replaced root-controlled acknowledgement")
''', str(public)], capture_output=True, check=False)
            self.assertEqual(writer.returncode, 0, writer.stderr)
            reader = subprocess.run(["setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", sys.executable, "-I", "-c", '''
import os,pathlib,sys
assert os.geteuid()==0
status=pathlib.Path("/proc/self/status").read_text()
assert next(line.split(":",1)[1].strip() for line in status.splitlines() if line.startswith("CapEff:"))=="0000000000000000"
try: pathlib.Path(sys.argv[1]).read_text()
except PermissionError: pass
else: raise AssertionError("private runtime directory unexpectedly readable")
assert pathlib.Path(sys.argv[2]).read_text()=="84\\n"
''', str(hidden), str(public)], capture_output=True, check=False)
            self.assertEqual(reader.returncode, 0, reader.stderr)
