#! /usr/bin/python
# -*- coding: utf-8 -*-

import sys
import socket
import struct
import threading
import SocketServer
import logging
from library.pylru import lrucache
from gevent import monkey


class DNS():
    def __init__(self):
        monkey.patch_all()

        self.dns_hosts = [
            '8.8.8.8',         # Google
            '8.8.4.4',
            '156.154.70.1',    # DnsAdvantage
            '156.154.71.1',
            '208.67.222.222',  # OpenDNS
            '208.67.220.220',
            #'198.153.192.1',  # Norton
            #'198.153.194.1',
            '74.207.247.4',
            '209.244.0.3',
            '8.26.56.26'
        ]
        self.dns_hosts_china = [
            '218.74.122.66',
            '218.74.122.74',
            '199.91.73.222',    # v2ex
            '178.79.131.110',
        ]

        self.dns_port = 53
        self.timeout = 20
        self.lru_cache = lrucache(100)

        logging.basicConfig(format='%(asctime)s | %(message)s')
        self.logger = logging.getLogger('tcpdns')
        self.logger.setLevel(logging.DEBUG)

        self.colors = {
            'pink': '\033[95m',
            'blue': '\033[94m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'red': '\033[91m',
            'end': '\033[0m',
        }

        self.server = None

    @staticmethod
    def hex_dump(src, width=16):
        hex_filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        result = []
        for i in xrange(0, len(src), width):
            s = src[i:i+width]
            hex_alpha_byte = ' '.join(['%02X' % ord(x) for x in s])
            printable = s.translate(hex_filter)
            result.append('%04X   %s   %s\n' % (i, hex_alpha_byte, printable))
        return ''.join(result)

    @staticmethod
    def byte_to_domain(s):
        domain = ''
        i = 0
        length = struct.unpack('!B', s[0:1])[0]

        while length != 0:
            i += 1
            domain += s[i:i+length]
            i += length
            length = struct.unpack('!B', s[i:i+1])[0]
            if length != 0:
                domain += '.'

        return domain  # 03www06google02cn00 => www.google.cn

    def query_dns(self, srv, port, query_data):
        # length
        buffer_len = struct.pack('!h', len(query_data))
        send_buffer = buffer_len + query_data
        data = None
        soc = None
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(self.timeout)  # set socket timeout
            soc.connect((srv, int(port)))
            soc.send(send_buffer)
            data = soc.recv(2048)
        except Exception, e:
            self.logger.info('%sERROR A%s | QueryDNS: %s' % (self.colors['red'], self.colors['end'], e.message))
        finally:
            if soc:
                soc.close()
            return data

    def transfer(self, query_data, address, srv):
        if not query_data:
            return

        domain = self.byte_to_domain(query_data[12:-4])
        query_type = struct.unpack('!h', query_data[-4:-2])[0]

        self.logger.info('%sToClient%s | domain: %s, query_type: %x, thread: %d' %
                         (self.colors['green'], self.colors['end'], domain, query_type, threading.activeCount()))
        sys.stdout.flush()

        response = None
        t_id = query_data[:2]
        key = query_data[2:].encode('hex')

        if self.lru_cache is not None:
            try:
                response = self.lru_cache[key]
                srv.sendto(t_id + response[4:], address)
                self.logger.info('%sLRUCache%s | Hit key: %s' % (self.colors['pink'], self.colors['end'], key))
            except KeyError:
                pass

        if response is not None:
            return

        for i in range(len(self.dns_hosts)):
            dns_host = self.dns_hosts[i]
            self.logger.info('%sQueryDNS%s | ip: %s' % (self.colors['blue'], self.colors['end'], dns_host))
            response = self.query_dns(dns_host, self.dns_port, query_data)

            if response is None:
                continue

            if self.lru_cache is not None:
                self.lru_cache[key] = response

            # udp dns packet no length
            srv.sendto(response[2:], address)  # send udp dns response back to client program
            break

        if response is None:
            self.logger.info('%sERROR %s | Tried many times and failed to resolve %s' %
                             (self.colors['red'], self.colors['end'], domain))

    class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
        def __init__(self, s, t):
            SocketServer.UDPServer.__init__(self, s, t)

    class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
        # Ctrl-C will cleanly kill all spawned threads
        daemon_threads = True
        # much faster rebinding
        allow_reuse_address = True

        def handle(self):
            thread_data = self.request[0]
            thread_address = self.client_address
            thread_socket = self.request[1]
            dns.transfer(thread_data, thread_address, thread_socket)

    def start(self):
        self.logger.info('Please wait program init....')

        self.server = self.ThreadedUDPServer(('0.0.0.0', 53), self.ThreadedUDPRequestHandler)

        self.logger.info('Init finished!')
        self.logger.info('Now you can set dns server to 127.0.0.1')

        self.server.serve_forever()
        self.server.shutdown()

if __name__ == '__main__':
    dns = DNS()
    dns.start()
