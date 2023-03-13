# -*- coding: utf-8 -*-
#! python3

"""
提取tls流的以下特征
Certificate_san_number
Certificate_validity

ClientHello_extention_number
ClientHello_extension_length
ClientHello_has_GREASE
ClientHello_length


ServerHello_CipherSuite

ServerKeyExchange_sig_len: 通过wireshark提取
"""

GREASE_EXTENSION_TYPE = {2570, 6682, 10794, 14906,
                         19018, 23130, 27242, 31354,
                         35466, 39578, 43690, 47802,
                         51914, 56026, 60138, 64250}
TLS_VERSION_BYTES = {b'\x03\x01', b'\x03\02', b'\x03\x03'}

def tls_multi_handshake(buf):
    i, n = 0, len(buf)
    hss = []
    while i + 3 <= n:
        try:
            hs = dpkt.ssl.TLSHandshake(buf[i:])
            hss.append(hs)
        except dpkt.NeedData:
            break
        i += len(hs)
    return hss, i

def has_GREASE_CipherSuite(ciphersuites):
    for cs in ciphersuites:
        if cs.name == 'GREASE':
            return True
    return False

def has_GREASE_Extension(extensions):
    for ext in extensions:
        if ext[0] in GREASE_EXTENSION_TYPE:
            return True
    return False

def has_GREASE(tlsClientHello):
    if has_GREASE_CipherSuite(tlsClientHello.ciphersuites):
        return 1
    if has_GREASE_Extension(tlsClientHello.extensions):
        return 1
    return 0

from datetime import datetime

import dpkt
import OpenSSL
import os
import pandas as pd
import socket

class Flow():
    def __init__(self, capture):
        self.capture = capture

        self.sip = None
        self.dip = None
        self.sport = None
        self.dport = 433

        self.Certificate_san_number = 0
        self.Certificate_validity = 0
        self.ClientHello_extention_number = 0
        self.ClientHello_extension_length = 0
        self.ClientHello_has_GREASE = 0
        self.ClientHello_length = 0
        self.ServerHello_CipherSuite = None
        # self.ServerKeyExchange_sig_len = 0

        self.parse_capture()

    def feature_extract(self, data, ip, tcp):
        if isinstance(data, dpkt.ssl.TLSClientHello):
            self.sip = socket.inet_ntoa(ip.src)
            self.dip = socket.inet_ntoa(ip.dst)
            self.sport = tcp.sport
            self.dport = tcp.dport

            tlsClientHello = data
            self.ClientHello_extention_number = len(tlsClientHello.extensions)
            self.ClientHello_extension_length = sum((len(x[1]) + 4) for x in tlsClientHello.extensions)
            self.ClientHello_has_GREASE = has_GREASE(tlsClientHello)
            self.ClientHello_length = len(tlsClientHello)

        if isinstance(data, dpkt.ssl.TLSServerHello):
            tlsServerHello = data
            self.ServerHello_CipherSuite = tlsServerHello.ciphersuite.code # int

        if isinstance(data, dpkt.ssl.TLSCertificate):
            tlsCertificate = data
            certs = tlsCertificate.certificates
            if certs:
                cert_0 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, certs[0])
                
                ext_cnt = cert_0.get_extension_count()
                for i in range(ext_cnt):
                    if cert_0.get_extension(i).get_short_name() == b'subjectAltName':
                        san = cert_0.get_extension(i)
                        self.Certificate_san_number = len(san.__str__().split(', '))
                        break

                before = datetime.strptime(cert_0.get_notBefore().decode()[:-7], '%Y%m%d')
                after = datetime.strptime(cert_0.get_notAfter().decode()[:-7], '%Y%m%d')
                self.Certificate_validity = (after - before).days

    def parse_capture(self):
        for n, (_, pkt) in enumerate(self.capture):
            eth = dpkt.ethernet.Ethernet(pkt)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    if tcp.data:
                        if tcp.data[0] == 22: # TLSHandshake
                            if tcp.data[1:3] in TLS_VERSION_BYTES: # tlsv1.0 - tlsv1.2
                                try:
                                    rcds, i = dpkt.ssl.tls_multi_factory(tcp.data)
                                except dpkt.ssl.SSL3Exception: # 已经检查过Version，理论上不会被except
                                    continue

                                # 保证得到的Handshake Record是完整的
                                if i < len(tcp.data):
                                    dport = tcp.dport
                                    seq = tcp.seq
                                    l = len(tcp.data) # segment的长度
                                    while i < len(tcp.data):
                                        try:
                                            _, _pkt = self.capture.__next__()
                                        except StopIteration:
                                            print('File ends.')
                                            break
                                        _eth = dpkt.ethernet.Ethernet(_pkt)
                                        if isinstance(_eth.data, dpkt.ip.IP):
                                            _ip = _eth.data
                                            if isinstance(_ip.data, dpkt.tcp.TCP):
                                                _tcp = _ip.data
                                                # 同一内容的分段
                                                if _tcp.dport == dport and _tcp.flags & 0x10 and _tcp.seq == l + seq:
                                                    tcp.data = tcp.data + _tcp.data
                                                    l += len(_tcp.data)
                                                    try:
                                                        _, i = dpkt.ssl.tls_multi_factory(tcp.data)
                                                    except dpkt.ssl.SSL3Exception: # bad TLS Versio
                                                        break
                                                    # 可能会i == len(tcp.data) Index out Range
                                                    if i < len(tcp.data) and tcp.data[i] != 22: # not handshake
                                                        break

                                try:
                                    rcds, _ = dpkt.ssl.tls_multi_factory(tcp.data)
                                except dpkt.ssl.SSL3Exception: # bad TLS Version
                                    continue
                                for r in rcds:
                                    try:
                                        hss, _ = tls_multi_handshake(r.data)
                                    except dpkt.ssl.SSL3Exception: # bad handshake type
                                        break
                                    for h in hss:
                                        self.feature_extract(h.data, ip, tcp)


    def get_features(self):
        features = {}
        attr = self.__dict__
        bin = {'capture'}
        for a in attr:
            if a not in bin:
                features[a] = attr[a]
        return features

# pre = 'chrome'
# pre = 'dingtalk'
# pre = 'edge'
# pre = 'feishu'
# pre = 'netease'
pre = 'qq'

tls_dir = pre + '/tls/'
features = []
for file in os.listdir(tls_dir):
    print('Processing %s ...' % file)
    # if file != '192.168.215.129_50077_111.63.59.36_443_TCP.pcap':
    #     continue
    

    with open(tls_dir + file, 'rb') as f:
        capture = dpkt.pcap.Reader(f)
        flow = Flow(capture)
        features.append(flow.get_features())
        pd.DataFrame(features).to_csv(pre + 'features.csv', index=None)
    


