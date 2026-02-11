#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redirector – rewrite specific URLs to different destinations.
Add your own rules in request_handler().
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy2 import ProxyRequestHandler, test

class RedirectorRequestHandler(ProxyRequestHandler):
    """Rewrite requests to different hosts/paths."""
    
    def request_handler(self, req, req_body):
        # Example 1: Redirect all google.com to example.com
        if 'google.com' in req.path:
            req.path = req.path.replace('google.com', 'example.com')
            print(f"[Redirector] Google -> Example: {req.path}")
        
        # Example 2: Block specific domains (return False = 403 Forbidden)
        if 'facebook.com' in req.path or 'instagram.com' in req.path:
            print("[Redirector] Blocked social media")
            return False  # sends 403
        
        # Example 3: Rewrite local development URLs
        if req.path.startswith('http://dev.local/'):
            req.path = req.path.replace('http://dev.local/', 'http://localhost:3000/')
            print(f"[Redirector] Dev redirect: {req.path}")
        
        # Return None = no modification to request body
        return None


if __name__ == '__main__':
    test(HandlerClass=RedirectorRequestHandler)
