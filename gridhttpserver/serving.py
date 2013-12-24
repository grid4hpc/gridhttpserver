# -*- coding: utf-8 -*-

#'Subclass' Werkzeug 0.8.3 to run with M2Crypto and
#mandatory certificate authentication.

from M2Crypto import SSL

import werkzeug.serving
import socket
import sys
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

class WSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """A request handler that implements WSGI dispatching."""

    def make_environ(self):
        environ = super(WSGIRequestHandler, self).make_environ()

        #update environment
        environ['wsgi.url_scheme'] = 'https'
        environ['HTTPS'] = '1'
        environ['x509_client_stack']=self.connection.cert_stack
        environ['x509_client_cert']=self.connection.cert_stack[0]

        return environ

    def handle(self):
        """Handles a request ignoring dropped connections."""
        rv = None
        try:
            rv = BaseHTTPRequestHandler.handle(self)
        except (socket.error, socket.timeout), e:
            self.connection_dropped(e)
        except Exception:
            if not is_ssl_error():
                raise
        if self.server.shutdown_signal:
            self.initiate_shutdown()
        return rv

def is_ssl_error(error=None):
    """Checks if the given error (or the current one) is an SSL error."""
    if error is None:
        error = sys.exc_info()[1]
    return isinstance(error, SSL.SSLError)

werkzeug.serving.is_ssl_error=is_ssl_error

class BaseWSGIServer(werkzeug.serving.BaseWSGIServer):
    """Simple single-threaded, single-process WSGI server."""
    multithread = False
    multiprocess = False
    request_queue_size = 128

    def __init__(self, host, port, app, handler=None,
                 passthrough_errors=False, ssl_context=None):
        #mostly copy of werkzeug __init__
        if handler is None:
            handler = WSGIRequestHandler
        self.address_family = werkzeug.serving.select_ip_version(host, port)
        HTTPServer.__init__(self, (host, int(port)), handler)
        self.app = app
        self.passthrough_errors = passthrough_errors
        self.shutdown_signal = False

        if ssl_context is None:
            raise RuntimeError("ssl_context is required for operation.")

        ssl_context.set_verify(ssl_context.get_verify_mode(),
                               ssl_context.get_verify_depth(),
                               self.verify_callback)

        self.socket = SSL.Connection(ssl_context, self.socket)
        self.ssl_context = ssl_context
        self.stack_cache = {}

    def verify_callback(self, ok, store):
        current_chain = store.get1_chain()
        dn = str(current_chain.pystack[0].get_subject())
        self.stack_cache[dn] = current_chain
        return ok

    def get_request(self):
        try:
            con, info = self.socket.accept()
            con.cert_stack = self.stack_cache.get(str(con.get_peer_cert().get_subject()), None)
        except (SSL.SSLError, AttributeError), e:
            return None, None
        return con, info

    def verify_request(self, request, client_address):
        if request is None:
            return False
        return True

from SocketServer import ThreadingMixIn, ForkingMixIn

class ThreadedWSGIServer(werkzeug.serving.ThreadingMixIn, BaseWSGIServer):
    """A WSGI server that does threading."""
    multithread = True

class ForkingWSGIServer(werkzeug.serving.ForkingMixIn, BaseWSGIServer):
    """A WSGI server that does forking."""
    multiprocess = True

    def __init__(self, host, port, app, processes=40, handler=None,
                 passthrough_errors=False, ssl_context=None):
        BaseWSGIServer.__init__(self, host, port, app, handler,
                                passthrough_errors, ssl_context)
        self.max_children = processes

def make_server(host, port, app=None, threaded=False, processes=1,
                request_handler=None, passthrough_errors=False,
                ssl_context=None):
    """Create a new server instance that is either threaded, or forks
    or just processes one request after another.
    """
    if threaded and processes > 1:
        raise ValueError("cannot have a multithreaded and "
                         "multi process server.")
    elif threaded:
        return ThreadedWSGIServer(host, port, app, request_handler,
                                  passthrough_errors, ssl_context)
    elif processes > 1:
        return ForkingWSGIServer(host, port, app, processes, request_handler,
                                 passthrough_errors, ssl_context)
    else:
        return BaseWSGIServer(host, port, app, request_handler,
                              passthrough_errors, ssl_context)

werkzeug.serving.make_server = make_server

from werkzeug.serving import run_simple as run_simple
