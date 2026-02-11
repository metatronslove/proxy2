#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP/HTTPS Intercept Proxy - Python 3.13+ Windows 11
Tested with curl, Chrome, Firefox
"""
import sys
import os
import socket
import ssl
import threading
import http.client
import urllib.parse
import gzip
import zlib
import time
import json
import re
import argparse
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from io import BytesIO
from subprocess import Popen, PIPE
from datetime import datetime
from urllib.parse import urlparse, parse_qsl

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

# ---------- Threading HTTPS Server ----------
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    address_family = socket.AF_INET6  # IPv6 enabled, but falls back to IPv4

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

# ---------- Main Proxy Handler ----------
class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 30
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    lock = threading.Lock()
    
    # Class variables for settings
    log_file = None
    no_color = False
    verbose = False

    def __init__(self, *args, **kwargs):
        self.connection_pool = {}
        self.start_time = None
        super().__init__(*args, **kwargs)

    # ---------- Connection Pooling ----------
    def get_connection(self, scheme, netloc):
        key = (scheme, netloc)
        if key in self.connection_pool:
            conn = self.connection_pool[key]
            try:
                # Test connection
                conn.sock.getpeername()
                return conn
            except:
                del self.connection_pool[key]
        
        if scheme == 'https':
            conn = http.client.HTTPSConnection(netloc, timeout=self.timeout)
        else:
            conn = http.client.HTTPConnection(netloc, timeout=self.timeout)
        self.connection_pool[key] = conn
        return conn

    # ---------- CONNECT (HTTPS Intercept) ----------
    def do_CONNECT(self):
        certs_ok = all([
            os.path.isfile(self.cakey),
            os.path.isfile(self.cacert),
            os.path.isfile(self.certkey),
            os.path.isdir(self.certdir)
        ])
        
        if certs_ok and self._check_openssl():
            self.connect_intercept()
        else:
            self.connect_relay()

    def _check_openssl(self):
        try:
            p = Popen(["openssl", "version"], stdout=PIPE, stderr=PIPE)
            p.communicate()
            return p.returncode == 0
        except:
            return False

    def connect_intercept(self):
        """HTTPS interception with dynamic certificate generation"""
        hostname = self.path.split(':')[0]
        certpath = os.path.join(self.certdir, f"{hostname}.crt")
        
        # Generate certificate if needed
        with self.lock:
            if not os.path.isfile(certpath):
                epoch = str(int(time.time() * 1000))
                try:
                    p1 = Popen(["openssl", "req", "-new", "-key", self.certkey,
                                "-subj", f"/CN={hostname}"], stdout=PIPE)
                    p2 = Popen(["openssl", "x509", "-req", "-days", "3650",
                                "-CA", self.cacert, "-CAkey", self.cakey,
                                "-set_serial", epoch, "-out", certpath],
                               stdin=p1.stdout, stderr=PIPE)
                    p2.communicate()
                except Exception as e:
                    self.log_error(f"Certificate generation failed: {e}")
                    self.connect_relay()
                    return
        
        # Send connection established
        self.send_response(200, 'Connection Established')
        self.end_headers()
        
        # Wrap socket with SSL
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certpath, keyfile=self.certkey)
            self.connection = context.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile("rb", self.rbufsize)
            self.wfile = self.connection.makefile("wb", self.wbufsize)
        except Exception as e:
            self.log_error(f"SSL wrap failed: {e}")
            return
        
        # Keep connection alive
        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        """Simple TCP relay for HTTPS without interception"""
        host, port = self.path.split(':', 1)
        port = int(port)
        
        try:
            # Connect to target
            remote = socket.create_connection((host, port), timeout=self.timeout)
            
            # Send 200 OK
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Relay data between client and server
            self._relay_data(self.connection, remote)
            
        except Exception as e:
            self.log_error(f"CONNECT relay failed: {e}")
            self.send_error(502)
            return

    def _relay_data(self, sock1, sock2):
        """Relay data between two sockets using threading (Windows compatible)"""
        stop_event = threading.Event()
        
        def forward(src, dst):
            try:
                while not stop_event.is_set():
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass
            finally:
                stop_event.set()
        
        t1 = threading.Thread(target=forward, args=(sock1, sock2))
        t2 = threading.Thread(target=forward, args=(sock2, sock1))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        
        # Wait for either thread to finish
        t1.join()
        t2.join()

    # ---------- HTTP Methods ----------
    def do_GET(self):
        self.start_time = time.time()
        
        # Special endpoint for CA certificate
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return
        
        # Parse request
        if self.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                self.path = f"https://{self.headers['Host']}{self.path}"
            else:
                self.path = f"http://{self.headers['Host']}{self.path}"
        
        # Read body if present
        content_length = self.headers.get('Content-Length')
        if content_length:
            req_body = self.rfile.read(int(content_length))
        else:
            req_body = None
        
        # Custom request handler
        req_body_modified = self.request_handler(self, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            self.headers['Content-Length'] = str(len(req_body))
        
        # Parse URL
        parsed = urlparse(self.path)
        scheme = parsed.scheme
        netloc = parsed.netloc
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        
        # Get connection from pool
        try:
            conn = self.get_connection(scheme, netloc)
            
            # Forward headers
            headers = dict(self.headers)
            headers['Host'] = netloc
            headers = self.filter_headers(headers)
            
            # Send request
            conn.request(self.command, path, req_body, headers)
            res = conn.getresponse()
            
            # Read response
            res_body = res.read()
            
            # Decode if compressed
            content_encoding = res.headers.get('Content-Encoding', 'identity')
            res_body_plain = self.decode_content_body(res_body, content_encoding)
            
            # Custom response handler
            res_body_modified = self.response_handler(self, req_body, res, res_body_plain)
            if res_body_modified is False:
                self.send_error(403)
                return
            elif res_body_modified is not None:
                res_body_plain = res_body_modified
                res_body = self.encode_content_body(res_body_plain, content_encoding)
                res.headers['Content-Length'] = str(len(res_body))
            
            # Filter response headers
            res_headers = self.filter_headers(dict(res.headers))
            
            # Send response
            self.send_response_only(res.status, res.reason)
            for k, v in res_headers.items():
                self.send_header(k, v)
            self.end_headers()
            
            if self.command != 'HEAD':
                self.wfile.write(res_body)
            
            # Log the transaction
            with self.lock:
                self.save_handler(self, req_body, res, res_body_plain)
                
        except Exception as e:
            self.log_error(f"Request failed: {e}")
            # Remove failed connection from pool
            key = (scheme, netloc)
            if key in self.connection_pool:
                del self.connection_pool[key]
            self.send_error(502)
            return

    def filter_headers(self, headers):
        """Remove hop-by-hop headers"""
        hop_by_hop = [
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers', 
            'transfer-encoding', 'upgrade', 'proxy-connection'
        ]
        
        filtered = {}
        for k, v in headers.items():
            if k.lower() not in hop_by_hop:
                # Filter accept-encoding
                if k.lower() == 'accept-encoding':
                    encodings = [e.strip() for e in v.split(',')]
                    supported = ['gzip', 'deflate', 'identity']
                    filtered_encodings = [e for e in encodings if e in supported]
                    if filtered_encodings:
                        filtered[k] = ', '.join(filtered_encodings)
                else:
                    filtered[k] = v
        
        return filtered

    def encode_content_body(self, text, encoding):
        """Encode body with specified encoding"""
        if isinstance(text, str):
            text = text.encode('utf-8')
            
        if encoding == 'identity':
            return text
        elif encoding == 'gzip':
            buf = BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                f.write(text)
            return buf.getvalue()
        elif encoding == 'deflate':
            return zlib.compress(text)
        else:
            return text

    def decode_content_body(self, data, encoding):
        """Decode body with specified encoding"""
        if encoding == 'identity':
            return data
        elif encoding == 'gzip':
            buf = BytesIO(data)
            with gzip.GzipFile(fileobj=buf) as f:
                return f.read()
        elif encoding == 'deflate':
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            return data

    def send_cacert(self):
        """Send CA certificate for download"""
        try:
            with open(self.cacert, 'rb') as f:
                data = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-x509-ca-cert')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.log_error(f"Failed to send CA cert: {e}")
            self.send_error(404)

    # ---------- Custom Hooks ----------
    def request_handler(self, req, req_body):
        """Override this to modify requests"""
        pass

    def response_handler(self, req, req_body, res, res_body):
        """Override this to modify responses"""
        pass

    def save_handler(self, req, req_body, res, res_body):
        """Log request/response details"""
        self.print_info(req, req_body, res, res_body)

    # ---------- Logging ----------
    def print_info(self, req, req_body, res, res_body):
        """Print concise request log"""
        duration = time.time() - self.start_time if self.start_time else 0
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Size formatting
        size = len(res_body) if res_body else 0
        if size > 1024:
            size_str = f"{size/1024:.1f} KB"
        elif size > 0:
            size_str = f"{size} B"
        else:
            size_str = "0 B"
        
        # Color by status
        status = res.status
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
        
        # Log line
        log_line = f"[{timestamp}] {client_ip}:{client_port} → {req.command} {req.path} → {status_str} ({size_str}) in {duration:.2f}s"
        print(log_line)
        
        # File logging
        if self.log_file:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "client": f"{client_ip}:{client_port}",
                "method": req.command,
                "url": req.path,
                "status": status,
                "size": size,
                "time": round(duration, 3)
            }
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry) + '\n')
            except:
                pass
        
        # Verbose mode - full details
        if self.verbose:
            self._print_verbose(req, req_body, res, res_body)
    
    def _print_verbose(self, req, req_body, res, res_body):
        """Print detailed headers and body"""
        print(with_color(33, f"\n{req.command} {req.path} {req.request_version}"))
        for k, v in req.headers.items():
            print(f"{k}: {v}")
        
        if req_body:
            self._print_body(req.headers.get('Content-Type', ''), req_body, "REQUEST BODY")
        
        print(with_color(36, f"\nHTTP/1.1 {res.status} {res.reason}"))
        for k, v in res.headers.items():
            print(f"{k}: {v}")
        
        if res_body:
            self._print_body(res.headers.get('Content-Type', ''), res_body, "RESPONSE BODY")
        print()
    
    def _print_body(self, content_type, body, title):
        """Pretty print request/response body"""
        if not body:
            return
        
        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8')
            except:
                body = repr(body)[:200]
        
        body = body[:2000]  # Limit output
        
        if 'application/x-www-form-urlencoded' in content_type:
            parsed = '\n'.join(f"{k:<20} {v}" for k, v in parse_qsl(body))
            print(with_color(32, f"==== {title} ====\n{parsed}\n"))
        elif 'application/json' in content_type:
            try:
                obj = json.loads(body)
                formatted = json.dumps(obj, indent=2)
                if len(formatted) > 2000:
                    formatted = formatted[:2000] + "\n... (truncated)"
                print(with_color(32, f"==== {title} ====\n{formatted}\n"))
            except:
                print(with_color(32, f"==== {title} ====\n{body}\n"))
        elif 'text/html' in content_type:
            title_match = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', body, re.I)
            if title_match:
                title_text = html.unescape(title_match.group(1))
                print(with_color(32, f"==== HTML TITLE ====\n{title_text}\n"))
        elif 'text/' in content_type and len(body) < 1024:
            print(with_color(32, f"==== {title} ====\n{body}\n"))

    # ---------- Other HTTP Methods ----------
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_HEAD = do_GET
    do_OPTIONS = do_GET

# ---------- HTTPS Server (Client -> Proxy over SSL) ----------
class ThreadingHTTPSServer(ThreadingHTTPServer):
    def get_request(self):
        request, client_address = self.socket.accept()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=join_with_script_dir('ca.crt'),
                               keyfile=join_with_script_dir('ca.key'))
        request = context.wrap_socket(request, server_side=True)
        return request, client_address

# ---------- Main ----------
def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    parser = argparse.ArgumentParser(description="HTTP/HTTPS Intercept Proxy")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("-b", "--bind", default="", help="Bind address (default: all interfaces)")
    parser.add_argument("--https-proxy", action="store_true", help="Run as HTTPS proxy")
    parser.add_argument("--log-file", help="Log file path (JSONL format)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    # Set handler class variables
    HandlerClass.log_file = args.log_file
    HandlerClass.no_color = args.no_color
    HandlerClass.verbose = args.verbose
    
    if args.https_proxy:
        ServerClass = ThreadingHTTPSServer
    
    HandlerClass.protocol_version = protocol
    server_address = (args.bind, args.port)
    
    try:
        httpd = ServerClass(server_address, HandlerClass)
        sa = httpd.socket.getsockname()
        scheme = "HTTPS" if args.https_proxy else "HTTP"
        print(f"Serving {scheme} Proxy on {sa[0]}:{sa[1]} ...")
        print("Press Ctrl+C to stop")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.server_close()
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    test()
