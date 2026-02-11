#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP/HTTPS intercept proxy for Python 3.
Original by @philipc, 2025 modernization + Windows ANSI + logging.
"""
import sys
import os
import socket
import ssl
import select
import http.client
import urllib.parse
import threading
import gzip
import zlib
import time
import json
import re
import argparse
import html
import queue
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from io import BytesIO
from subprocess import Popen, PIPE
from datetime import datetime

# ---------- Windows ANSI color support ----------
def enable_windows_ansi():
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass
enable_windows_ansi()

def with_color(code, text):
    return f"\x1b[{code}m{text}\x1b[0m"

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)

# ---------- Common server base ----------
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

class ThreadingHTTPSServer(ThreadingHTTPServer):
    """HTTPS proxy server (client -> proxy over SSL)"""
    def __init__(self, *args, **kwargs):
        self.cakey = join_with_script_dir('ca.key')
        self.cacert = join_with_script_dir('ca.crt')
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, client_address = self.socket.accept()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.cacert, keyfile=self.cakey)
        request = context.wrap_socket(request, server_side=True)
        return request, client_address

# ---------- Main proxy handler ----------
class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 5
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    lock = threading.Lock()

    # Class-level settings (can be changed from test())
    log_file = None
    no_color = False
    verbose = False

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        self.start_time = None
        super().__init__(*args, **kwargs)

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return
        self.log_message(format, *args)

    # ---------- CONNECT (HTTPS interception) ----------
    def do_CONNECT(self):
        # Check if all certificate files exist
        certs_ok = (os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and
                    os.path.isfile(self.certkey) and os.path.isdir(self.certdir))
        if certs_ok and self._check_openssl():
            self.connect_intercept()
        else:
            if not certs_ok:
                self.log_message("WARNING: Certificate files missing, HTTPS intercept disabled")
            self.connect_relay()

    def _check_openssl(self):
        """Return True if openssl is in PATH."""
        try:
            Popen(["openssl", "version"], stdout=PIPE, stderr=PIPE).communicate()
            return True
        except FileNotFoundError:
            self.log_message("ERROR: openssl not found in PATH, HTTPS intercept disabled")
            return False

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = os.path.join(self.certdir, f"{hostname}.crt")

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = str(int(time.time() * 1000))
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey,
                            "-subj", f"/CN={hostname}"], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650",
                            "-CA", self.cacert, "-CAkey", self.cakey,
                            "-set_serial", epoch, "-out", certpath],
                           stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.send_response(200, 'Connection Established')
        self.end_headers()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certpath, keyfile=self.certkey)
        self.connection = context.wrap_socket(self.connection, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    # ---------- Regular HTTP methods ----------
    def do_GET(self):
        self.start_time = time.time()
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        # Make absolute URL if missing
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = f"https://{req.headers['Host']}{req.path}"
            else:
                req.path = f"http://{req.headers['Host']}{req.path}"

        # Custom request handler (override in subclass)
        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-Length'] = str(len(req_body))

        u = urllib.parse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc

        # Convert headers to list of tuples and filter
        req_headers = self._headers_to_tuples(req.headers)
        req_headers = self.filter_headers(req_headers)

        # Reuse connection or create new
        origin = (scheme, netloc)
        if not hasattr(self.tls, 'conns'):
            self.tls.conns = {}
        if origin not in self.tls.conns:
            if scheme == 'https':
                self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
            else:
                self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
        conn = self.tls.conns[origin]

        try:
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
        except Exception:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        # Read response body
        res_body = res.read()
        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        # Custom response handler
        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            # Update content-length if needed
            if 'Content-Length' in res.headers:
                res.headers['Content-Length'] = str(len(res_body))

        # Filter response headers
        res_headers = self._headers_to_tuples(res.headers)
        res_headers = self.filter_headers(res_headers)

        # Send response to client
        self.wfile.write(f"{self.protocol_version} {res.status} {res.reason}\r\n".encode('latin-1'))
        for k, v in res_headers:
            self.wfile.write(f"{k}: {v}\r\n".encode('latin-1'))
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        # Save / log (with lock)
        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def _headers_to_tuples(self, headers):
        """Convert http.client.HTTPMessage or dict to list of (name, value) tuples."""
        if hasattr(headers, 'items'):   # dict-like
            return list(headers.items())
        elif hasattr(headers, 'getheaders'):  # HTTPResponse.headers
            items = []
            for k in headers.keys():
                for v in headers.get_all(k):
                    items.append((k, v))
            return items
        else:
            return []

    def filter_headers(self, headers_tuples):
        """Remove hop-by-hop headers and unsupported encodings."""
        hop_by_hop = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
                      'te', 'trailers', 'transfer-encoding', 'upgrade'}
        result = []
        for k, v in headers_tuples:
            kl = k.lower()
            if kl in hop_by_hop:
                continue
            if kl == 'accept-encoding':
                encodings = [x.strip() for x in v.split(',')]
                filtered = [e for e in encodings if e in ('identity', 'gzip', 'x-gzip', 'deflate')]
                if filtered:
                    result.append((k, ', '.join(filtered)))
                continue
            result.append((k, v))
        return result

    def encode_content_body(self, text, encoding):
        if isinstance(text, str):
            text = text.encode('utf-8')
        if encoding == 'identity':
            return text
        elif encoding in ('gzip', 'x-gzip'):
            buf = BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                f.write(text)
            return buf.getvalue()
        elif encoding == 'deflate':
            return zlib.compress(text)
        else:
            raise ValueError(f"Unknown Content-Encoding: {encoding}")

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            return data
        elif encoding in ('gzip', 'x-gzip'):
            buf = BytesIO(data)
            with gzip.GzipFile(fileobj=buf) as f:
                return f.read()
        elif encoding == 'deflate':
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise ValueError(f"Unknown Content-Encoding: {encoding}")

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()
        self.send_response(200, 'OK')
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    # ---------- Customisable hooks ----------
    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        """Log request details to console and optional file."""
        self.print_info(req, req_body, res, res_body)

    # ---------- Rich logging ----------
    def print_info(self, req, req_body, res, res_body):
        duration = time.time() - self.start_time if self.start_time else 0
        client_ip, client_port = self.client_address
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Build concise log line
        method = req.command
        url = req.path
        status = res.status
        size = len(res_body) if res_body else 0
        size_str = f"{size/1024:.1f} KB" if size > 1024 else f"{size} B"

        # Color based on status
        if not self.no_color:
            if status < 200:
                color = 37  # white
            elif status < 300:
                color = 32  # green
            elif status < 400:
                color = 36  # cyan
            elif status < 500:
                color = 33  # yellow
            else:
                color = 31  # red
            status_str = with_color(color, str(status))
        else:
            status_str = str(status)

        log_line = (f"[{timestamp}] {client_ip}:{client_port} → {method} {url} "
                    f"→ {status_str} ({size_str}) in {duration:.2f}s")

        # Print to console
        print(log_line)

        # Optional file log (JSONL)
        if self.log_file:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "client": f"{client_ip}:{client_port}",
                "method": method,
                "url": url,
                "status": status,
                "size": size,
                "time": round(duration, 3)
            }
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')

        # Verbose mode: show full headers and body preview
        if self.verbose:
            self._print_verbose(req, req_body, res, res_body)

    def _print_verbose(self, req, req_body, res, res_body):
        """Original detailed dump (headers, JSON, cookies, etc.)"""
        def parse_qsl(s):
            return '\n'.join(f"{k:<20} {v}" for k, v in urllib.parse.parse_qsl(s, keep_blank_values=True))

        print(with_color(33, f"{req.command} {req.path} {req.request_version}"))
        for k, v in self._headers_to_tuples(req.headers):
            print(f"{k}: {v}")

        u = urllib.parse.urlsplit(req.path)
        if u.query:
            print(with_color(32, f"==== QUERY PARAMETERS ====\n{parse_qsl(u.query)}\n"))

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print(with_color(32, f"==== COOKIE ====\n{cookie}\n"))

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].encode().decode('base64')
            print(with_color(31, f"==== BASIC AUTH ====\n{token}\n"))

        if req_body:
            self._print_body(req.headers.get('Content-Type', ''), req_body, "REQUEST BODY")

        print(with_color(36, f"HTTP/{res.version/10:.1f} {res.status} {res.reason}"))
        for k, v in self._headers_to_tuples(res.headers):
            print(f"{k}: {v}")

        cookies = res.headers.get_all('Set-Cookie', [])
        if cookies:
            print(with_color(31, "==== SET-COOKIE ====\n" + '\n'.join(cookies) + "\n"))

        if res_body:
            self._print_body(res.headers.get('Content-Type', ''), res_body, "RESPONSE BODY")

    def _print_body(self, content_type, body, title):
        if not body:
            return
        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8')
            except UnicodeDecodeError:
                body = repr(body)[:200]
        body = body[:2000]  # limit output

        if content_type.startswith('application/x-www-form-urlencoded'):
            parsed = '\n'.join(f"{k:<20} {v}" for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True))
            print(with_color(32, f"==== {title} ====\n{parsed}\n"))
        elif content_type.startswith('application/json'):
            try:
                obj = json.loads(body)
                formatted = json.dumps(obj, indent=2)
                if len(formatted) > 2000:
                    formatted = formatted[:2000] + "\n... (truncated)"
                print(with_color(32, f"==== {title} ====\n{formatted}\n"))
            except:
                print(with_color(32, f"==== {title} ====\n{body}\n"))
        elif content_type.startswith('text/html'):
            m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', body, re.I)
            if m:
                title_text = html.unescape(m.group(1))
                print(with_color(32, f"==== HTML TITLE ====\n{title_text}\n"))
        elif content_type.startswith('text/') and len(body) < 1024:
            print(with_color(32, f"==== {title} ====\n{body}\n"))

    # ---------- Other HTTP methods ----------
    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

# ---------- Command line & server start ----------
def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    parser = argparse.ArgumentParser(description="HTTP/HTTPS intercept proxy")
    parser.add_argument("-p", "--port", type=int, default=8080, help="port to listen on")
    parser.add_argument("-b", "--bind", default="", help="bind address (default: all interfaces)")
    parser.add_argument("--https-proxy", action="store_true", help="run as HTTPS proxy (client->proxy SSL)")
    parser.add_argument("--log-file", help="append JSONL logs to this file")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--verbose", action="store_true", help="show full headers and body preview")
    args = parser.parse_args()

    # Apply settings to handler class
    HandlerClass.log_file = args.log_file
    HandlerClass.no_color = args.no_color
    HandlerClass.verbose = args.verbose

    if args.https_proxy:
        ServerClass = ThreadingHTTPSServer

    HandlerClass.protocol_version = protocol
    server_address = (args.bind, args.port)
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    scheme = "HTTPS" if args.https_proxy else "HTTP"
    print(f"Serving {scheme} Proxy on {sa[0]}:{sa[1]} ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.server_close()

if __name__ == '__main__':
    test()
