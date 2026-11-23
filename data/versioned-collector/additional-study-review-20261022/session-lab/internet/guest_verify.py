#!/usr/bin/env python3
"""Run as the guest user on the NAT adapter: address, route, DNS, HTTPS, an empty Downloads folder, and which
common network programs the guest has. Prints one JSON object."""
import json
import os
import shutil
import socket
import subprocess
import urllib.request


def run(*argv):
    exe = shutil.which(argv[0]) or next((p for p in ("/usr/sbin/" + argv[0], "/usr/bin/" + argv[0])
                                         if os.path.exists(p)), argv[0])
    try:
        return subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=30).stdout
    except Exception as error:   # recorded, not raised
        return "error: %r" % error


r = {"addr": run("ip", "-4", "-o", "addr", "show"), "route": run("ip", "-4", "route"),
     "resolv": open("/etc/resolv.conf").read() if os.path.exists("/etc/resolv.conf") else None}
try:
    r["dns"] = sorted({a[4][0] for a in socket.getaddrinfo("example.com", 443, socket.AF_INET)})
except Exception as error:
    r["dns_error"] = repr(error)
r["http"] = {}
for url in ("https://example.com/", "https://www.wikipedia.org/"):
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            r["http"][url] = response.status
    except Exception as error:
        r["http"][url] = repr(error)
home = os.path.expanduser("~")
d = os.path.join(home, "Downloads")
r["downloads"] = sorted(os.listdir(d)) if os.path.isdir(d) else None
r["tools"] = {t: shutil.which(t) for t in ("curl", "wget", "git", "ssh", "openssl", "dig", "ping", "apt-get")}
print(json.dumps(r, sort_keys=True))
