"""Benign crawler: fetch the start page, follow its links (html.parser), then fetch numbered pages up to 100 in total."""
import json, sys, urllib.request
from html.parser import HTMLParser
host = sys.argv[1]; assert host == "10.0.0.1"
class Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links += [v for k, v in attrs if k == "href" and v and v.startswith("/")]
queue, seen, ok, fail = ["/"], set(), 0, 0
i = 0
while len(seen) < 100:
    path = queue.pop(0) if queue else "/docs/page%d.html" % i
    i += 1
    if path in seen:
        continue
    seen.add(path)
    try:
        with urllib.request.urlopen("http://%s%s" % (host, path), timeout=3) as r:
            parser = Links(); parser.feed(r.read().decode("latin-1")); ok += 1
            queue += parser.links[:5]
    except OSError:
        fail += 1
print(json.dumps({"workload": "http_crawl", "ok": ok, "failed": fail}))
sys.exit(0 if ok else 1)
