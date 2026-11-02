"""Wait for the authenticated loopback server without logging credentials."""
import base64
import os
import time
import urllib.error
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
request = urllib.request.Request("http://127.0.0.1:4096/api/info", headers={
    "Authorization": "Basic " + base64.b64encode(
        ("opencode:" + os.environ["OPENCODE_PASSWORD"]).encode()).decode(),
})
deadline = time.monotonic() + 45
while time.monotonic() < deadline:
    try:
        with opener.open(request, timeout=2) as response:
            if response.status == 200:
                raise SystemExit(0)
    except (urllib.error.URLError, TimeoutError):
        time.sleep(0.2)
raise SystemExit(1)
