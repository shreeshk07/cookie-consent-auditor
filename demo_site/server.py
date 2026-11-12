"""Local demo site used to try the auditor without touching real websites.

Routes
  /bad    Sets tracking cookies (Google Analytics, Meta Pixel, Google Ads) on page load,
          before the visitor touches the consent banner. Expected verdict: FAIL.
  /good   Sets only a session cookie. Tracking scripts load only after "Accept" is
          clicked. Expected verdict: PASS.
  /mixed  Sets a session cookie plus one unrecognised persistent identifier cookie.
          Expected verdict: REVIEW.

Run it with:  python -m demo_site.server  (listens on http://127.0.0.1:8765)
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BANNER = """
<div id="cookie-banner" style="position:fixed;bottom:0;left:0;right:0;background:#222;color:#fff;padding:16px">
  We use cookies. <button id="accept">Accept</button> <button id="reject">Reject</button>
</div>
"""

TRACKERS_JS = """
function setCookie(n, v, days) {
  var d = new Date(); d.setTime(d.getTime() + days * 86400000);
  document.cookie = n + "=" + v + "; expires=" + d.toUTCString() + "; path=/";
}
setCookie("_ga", "GA1.1.1234567890.1700000000", 400);
setCookie("_ga_ABC123XYZ", "GS1.1.1700000000.1.0.1700000000.0", 400);
setCookie("_gid", "GA1.1.987654321.1700000000", 1);
setCookie("_fbp", "fb.1.1700000000000.1122334455", 90);
setCookie("_gcl_au", "1.1.556677889.1700000000", 90);
"""

PAGES = {
    "/bad": {
        "title": "Demo shop (sets trackers before consent)",
        "headers": ["PHPSESSID=abc123def456; Path=/; HttpOnly; SameSite=Lax"],
        "script": TRACKERS_JS,
        "banner": True,
    },
    "/good": {
        "title": "Demo shop (waits for consent)",
        "headers": ["PHPSESSID=abc123def456; Path=/; HttpOnly; SameSite=Lax"],
        "script": 'document.getElementById("accept").addEventListener("click", function(){' + TRACKERS_JS + "});",
        "banner": True,
    },
    "/mixed": {
        "title": "Demo shop (unrecognised identifier cookie)",
        "headers": [
            "PHPSESSID=abc123def456; Path=/; HttpOnly; SameSite=Lax",
            "visitor_token=7f3a9c1e5b2d48a6b0c4e8d2f1a39b57; Path=/; Max-Age=31536000",
        ],
        "script": "",
        "banner": True,
    },
}


def render(page: dict) -> str:
    # The consent button handlers must exist before the tracker script runs on /good.
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{page['title']}</title></head>
<body><h1>{page['title']}</h1><p>Demo content.</p>{BANNER if page['banner'] else ''}
<script>{page['script']}</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/":
            body = "<h1>Demo</h1><ul>" + "".join(f'<li><a href="{p}">{p}</a></li>' for p in PAGES) + "</ul>"
            self._send(200, body, [])
        elif path in PAGES:
            page = PAGES[path]
            self._send(200, render(page), page["headers"])
        else:
            self._send(404, "Not found", [])

    def _send(self, status, body, set_cookies):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for value in set_cookies:
            self.send_header("Set-Cookie", value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence request logging
        pass


def start(port: int = 8765) -> ThreadingHTTPServer:
    """Start the server on a background thread and return it (call .shutdown() to stop)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Demo site on http://127.0.0.1:8765  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
