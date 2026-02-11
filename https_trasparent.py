#!/usr/bin/env python3
from proxy2 import ThreadingHTTPSServer, ProxyRequestHandler, test

if __name__ == '__main__':
    test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPSServer)
