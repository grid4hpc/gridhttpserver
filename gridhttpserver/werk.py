# -*- encoding: utf-8 -*-

import os, sys, logging, socket, time
import argparse
import importlib

from M2Crypto import SSL, X509

import gridhttpserver.certlib; gridhttpserver.certlib.monkey()
import gridhttpserver.serving

log = logging.getLogger(__name__)

class AccessLog(object):
    # LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    log_format = '%(host)s - - %(asctime)s "%(request)s" %(status)s %(response_size)s "%(referer)s" "%(user_agent)s"'
    datefmt = "[%d/%b/%Y:%H:%M:%S %z]"
    def __init__(self):
        self.log = logging.getLogger('access_log')

    def __call__(self, host='-', request='-', status='200', response_size='-',
                 referer='-', user_agent='-'):
        asctime = time.strftime(self.datefmt)
        status = str(status)
        self.log.info(self.log_format % locals())

access_log = AccessLog()

def setup_logging(conf):
    levelmap = {
        0: logging.FATAL,
        1: logging.ERROR,
        2: logging.WARNING,
        3: logging.INFO,
        4: logging.DEBUG
        }
    level = levelmap.get(conf.getint('httpd', 'debug_level', 4), logging.ERROR)
    logging.root.setLevel(logging.DEBUG)

    access_log = logging.getLogger('access_log')
    access_log_filename = conf.get('httpd', 'access_log', None)
    if access_log_filename:
        handler = logging.FileHandler(access_log_filename, encoding='utf-8')
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.setLevel(logging.INFO)
        access_log.addHandler(handler)

    class AccessLogFilter(object):
        def filter(self, record):
            if record.name == 'access_log':
                return False
            return True

    error_log_filename = conf.get('httpd', 'error_log', None)
    error_format = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                                     datefmt='%a %b %d %H:%M:%S %Y')
    if sys.stdout.isatty():
        #then in tty log there also
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(error_format)
        handler.setLevel(level)
        logging.root.addHandler(handler)

    if error_log_filename:
        handler = logging.FileHandler(error_log_filename, encoding='utf-8')
        handler.setFormatter(error_format)
        handler.setLevel(level)
        handler.addFilter(AccessLogFilter())
        logging.root.addHandler(handler)

    class StdoutInterceptor(object):
        def __init__(self, logname='error_log'):
            self.log = logging.getLogger(logname)

        def write(self, message):
            msg = message.strip("\n")
            if len(msg) > 0:
                self.log.error('%s', msg)

    sys.stdout = StdoutInterceptor('stdout')
    sys.stderr = StdoutInterceptor('stderr')


class Server:
    def __init__(self):
        self.bindaddr = '0.0.0.0'
        self.port = 5053
        self.ssl_cert = '/etc/grid-security/containercert.pem'
        self.ssl_key = '/etc/grid-security/containerkey.pem'
        self.ssl_cafile = None
        self.ssl_capath = '/etc/grid-security/certificates'
        self.wsgi = None
        self.app = None

    def parse_args(self):
        parser = argparse.ArgumentParser(description='WSGI server with proxy certificate support')

        parser.add_argument('-i', '--ip',
            dest = 'bindaddr', action = 'store', default = '0.0.0.0', help = 'server bind address')

        parser.add_argument('-p', '--port',
            dest = 'port', action = 'store', type = int, default = 5053, help ='server port')

        parser.add_argument('-c', '--ssl_cert',
            dest = 'ssl_cert', action = 'store', default = '/etc/grid-security/containercert.pem', help = 'server ssl certificate')

        parser.add_argument('-k', '--ssl_key',
            dest = 'ssl_key', action = 'store', default = '/etc/grid-security/containerkey.pem' , help = 'server ssl private key')

        parser.add_argument('--ssl_cafile',
            dest = 'ssl_cafile', action = 'store', default = None)

        parser.add_argument('--ssl_capath',
            dest = 'ssl_capath', action = 'store', default = '/etc/grid-security/certificates')

        parser.add_argument('-w', '--wsgi',
            dest = 'wsgi', action = 'store', help = 'WSGI application loader')

        opt = parser.parse_args()
        self.bindaddr=opt.bindaddr
        self.port=opt.port
        self.ssl_cert = opt.ssl_cert
        self.ssl_key = opt.ssl_key
        self.ssl_cafile = opt.ssl_cafile
        self.ssl_capath = opt.ssl_capath
        self.wsgi = opt.wsgi

    def application(self):
        if self.wsgi is not None:
            try:
                module, method = self.wsgi.rsplit(":",1)
                m=importlib.import_module(module)
                method = getattr(importlib.import_module(module), method)
                return method()
            except:
                log.error("Failed to load application: %s" % self.wsgi)
                sys.exit(1)
        log.error("No application defined")
        sys.exit(1)

    def start(self):
        """Subscribe all engine plugins and start the engine."""

        self.app = self.application()

        try:
            ssl_certificate = X509.load_cert(self.ssl_cert)
        except Exception, exc:
            log.error("Failed to load certificate: %s" % str(exc))
            sys.exit(1)
        ctx = SSL.Context('sslv23')
        ctx.set_session_id_ctx("gridhttpserver-xxx") #?????
        try:
            ctx.load_cert(self.ssl_cert, self.ssl_key)
        except Exception, exc:
            log.error("Failed to load key: %s" % str(exc))
            sys.exit(1)
        ctx.load_verify_locations(cafile=self.ssl_cafile, capath=self.ssl_capath)
        ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 20)
        ctx.set_cipher_list("ALL:NULL:eNULL")
        os.environ['OPENSSL_ALLOW_PROXY_CERTS'] = '1'

        #FIXME
        #setup_logging(conf)
        try:
            gridhttpserver.serving.run_simple(self.bindaddr, self.port, self.app, ssl_context=ctx,
                               use_reloader=False, use_debugger=True)
        except Exception, exc:
            raise

if __name__ == '__main__':
    server = Server()
    server.parse_args()
    server.start()
