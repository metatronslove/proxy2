#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
User-Agent changer example.
Runs on port 8080 by default, or specify custom port:
    python uachanger.py --port 8000
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy2 import ProxyRequestHandler, test

class UAChangerRequestHandler(ProxyRequestHandler):
    """Change User-Agent to Internet Explorer 5.01 (Windows 98)"""
    
    def request_handler(self, req, req_body):
        # req.headers is a http.client.HTTPMessage (dict-like)
        req.headers['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 5.01; Windows 98)'
        
        # Optional: log the change
        if self.verbose:
            print(f"[UAChanger] Changed User-Agent for {req.path}")


if __name__ == '__main__':
    # Accept command-line arguments (port, bind, etc.)
    test(HandlerClass=UAChangerRequestHandler)
