import time
from datetime import datetime
import csv
from sslyze import *
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_
import pandas as pd
import ssl
import socket
import json
import math
from ocspchecker import ocspchecker
from OpenSSL import crypto
import argparse


import hashlib
from cryptography.x509 import load_pem_x509_certificate



#++++++++++++++++++++++++++++++++++#

parser = argparse.ArgumentParser()
parser.add_argument('-ho','--host', dest='host',type=str, required=False)
parser.add_argument('-p','--port', dest='port',type=int, required=False, default=443)
parser.add_argument('-holi','--hostlist', dest='holi', required=False)
parser.add_argument('-save_path_csv','--path2savefile', dest='save_path_csv', required=False, default='result.csv')
args = parser.parse_args()
CIPHERS_list=[
'ECDHE-ECDSA-AES256-GCM-SHA384',
'ECDHE-RSA-AES256-GCM-SHA384',
'DHE-DSS-AES256-GCM-SHA384',
'DHE-RSA-AES256-GCM-SHA384',
'ECDHE-ECDSA-CHACHA20-POLY1305',
'ECDHE-RSA-CHACHA20-POLY1305',
'DHE-RSA-CHACHA20-POLY1305',
'ECDHE-ECDSA-AES256-CCM8',
'ECDHE-ECDSA-AES256-CCM',
'DHE-RSA-AES256-CCM8',
'DHE-RSA-AES256-CCM',
'ECDHE-ECDSA-ARIA256-GCM-SHA384',
'ECDHE-ARIA256-GCM-SHA384',
'DHE-DSS-ARIA256-GCM-SHA384',
'DHE-RSA-ARIA256-GCM-SHA384',
'ADH-AES256-GCM-SHA384',
'ECDHE-ECDSA-AES128-GCM-SHA256',
'ECDHE-RSA-AES128-GCM-SHA256',
'DHE-DSS-AES128-GCM-SHA256',
'DHE-RSA-AES128-GCM-SHA256',
'ECDHE-ECDSA-AES128-CCM8',
'ECDHE-ECDSA-AES128-CCM',
'DHE-RSA-AES128-CCM8',
'DHE-RSA-AES128-CCM',
'ECDHE-ECDSA-ARIA128-GCM-SHA256',
'ECDHE-ARIA128-GCM-SHA256',
'DHE-DSS-ARIA128-GCM-SHA256',
'DHE-RSA-ARIA128-GCM-SHA256',
'ADH-AES128-GCM-SHA256',
'ECDHE-ECDSA-AES256-SHA384',
'ECDHE-RSA-AES256-SHA384',
'DHE-RSA-AES256-SHA256',
'DHE-DSS-AES256-SHA256',
'ECDHE-ECDSA-CAMELLIA256-SHA384',
'ECDHE-RSA-CAMELLIA256-SHA384',
'DHE-RSA-CAMELLIA256-SHA256',
'DHE-DSS-CAMELLIA256-SHA256',
'ADH-AES256-SHA256',
'ADH-CAMELLIA256-SHA256',
'ECDHE-ECDSA-AES128-SHA256',
'ECDHE-RSA-AES128-SHA256',
'DHE-RSA-AES128-SHA256',
'DHE-DSS-AES128-SHA256',
'ECDHE-ECDSA-CAMELLIA128-SHA256',
'ECDHE-RSA-CAMELLIA128-SHA256',
'DHE-RSA-CAMELLIA128-SHA256',
'DHE-DSS-CAMELLIA128-SHA256',
'ADH-AES128-SHA256',
'ADH-CAMELLIA128-SHA256',
'ECDHE-ECDSA-AES256-SHA',
'ECDHE-RSA-AES256-SHA',
'DHE-RSA-AES256-SHA',
'DHE-DSS-AES256-SHA',
'DHE-RSA-CAMELLIA256-SHA',
'DHE-DSS-CAMELLIA256-SHA',
'AECDH-AES256-SHA',
'ADH-AES256-SHA',
'ADH-CAMELLIA256-SHA',
'ECDHE-ECDSA-AES128-SHA',
'ECDHE-RSA-AES128-SHA',
'DHE-RSA-AES128-SHA',
'DHE-DSS-AES128-SHA',
'DHE-RSA-SEED-SHA',
'DHE-DSS-SEED-SHA',
'DHE-RSA-CAMELLIA128-SHA',
'DHE-DSS-CAMELLIA128-SHA',
'AECDH-AES128-SHA',
'ADH-AES128-SHA',
'ADH-SEED-SHA',
'ADH-CAMELLIA128-SHA',
'RSA-PSK-AES256-GCM-SHA384',
'DHE-PSK-AES256-GCM-SHA384',
'RSA-PSK-CHACHA20-POLY1305',
'DHE-PSK-CHACHA20-POLY1305',
'ECDHE-PSK-CHACHA20-POLY1305',
'DHE-PSK-AES256-CCM8',
'DHE-PSK-AES256-CCM',
'RSA-PSK-ARIA256-GCM-SHA384',
'DHE-PSK-ARIA256-GCM-SHA384',
'AES256-GCM-SHA384',
'AES256-CCM8',
'AES256-CCM',
'ARIA256-GCM-SHA384',
'PSK-AES256-GCM-SHA384',
'PSK-CHACHA20-POLY1305',
'PSK-AES256-CCM8',
'PSK-AES256-CCM',
'PSK-ARIA256-GCM-SHA384',
'RSA-PSK-AES128-GCM-SHA256',
'DHE-PSK-AES128-GCM-SHA256',
'DHE-PSK-AES128-CCM8',
'DHE-PSK-AES128-CCM',
'RSA-PSK-ARIA128-GCM-SHA256',
'DHE-PSK-ARIA128-GCM-SHA256',
'AES128-GCM-SHA256',
'AES128-CCM8',
'AES128-CCM',
'ARIA128-GCM-SHA256',
'PSK-AES128-GCM-SHA256',
'PSK-AES128-CCM8',
'PSK-AES128-CCM',
'PSK-ARIA128-GCM-SHA256',
'AES256-SHA256',
'CAMELLIA256-SHA256',
'AES128-SHA256',
'CAMELLIA128-SHA256',
'ECDHE-PSK-AES256-CBC-SHA384',
'ECDHE-PSK-AES256-CBC-SHA',
'SRP-DSS-AES-256-CBC-SHA',
'SRP-RSA-AES-256-CBC-SHA',
'SRP-AES-256-CBC-SHA',
'RSA-PSK-AES256-CBC-SHA384',
'DHE-PSK-AES256-CBC-SHA384',
'RSA-PSK-AES256-CBC-SHA',
'DHE-PSK-AES256-CBC-SHA',
'ECDHE-PSK-CAMELLIA256-SHA384',
'RSA-PSK-CAMELLIA256-SHA384',
'DHE-PSK-CAMELLIA256-SHA384',
'AES256-SHA',
'CAMELLIA256-SHA',
'PSK-AES256-CBC-SHA384',
'PSK-AES256-CBC-SHA',
'PSK-CAMELLIA256-SHA384',
'ECDHE-PSK-AES128-CBC-SHA256',
'ECDHE-PSK-AES128-CBC-SHA',
'SRP-DSS-AES-128-CBC-SHA',
'SRP-RSA-AES-128-CBC-SHA',
'SRP-AES-128-CBC-SHA',
'RSA-PSK-AES128-CBC-SHA256',
'DHE-PSK-AES128-CBC-SHA256',
'RSA-PSK-AES128-CBC-SHA',
'DHE-PSK-AES128-CBC-SHA',
'ECDHE-PSK-CAMELLIA128-SHA256',
'RSA-PSK-CAMELLIA128-SHA256',
'DHE-PSK-CAMELLIA128-SHA256',
'AES128-SHA',
'SEED-SHA',
'CAMELLIA128-SHA',
'IDEA-CBC-SHA',
'PSK-AES128-CBC-SHA256',
'PSK-AES128-CBC-SHA',
'PSK-CAMELLIA128-SHA256'
]


#++++++++++++++++++++++++++++++++++#
class analyzeCertificate:
    def __init__(self, host, port, holi, CIPHERS_list) -> None:
        self.host = host
        self.holi = holi
        if not holi:
            self.read = None
        else:
            self.read_host()
            
        self.port = port
        self.now = datetime.now()
        self.CIPHERS_list = CIPHERS_list
        pass

    #------------------------------#
    def read_host(self):
        data = pd.read_csv(self.holi)
        self.read = data['Domain'].tolist()
    #------------------------------#    
    def get_cert(self):
        try:
            ctx = ssl.create_default_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            ssock = ctx.wrap_socket(sock,server_hostname=self.host)
            ssock.connect((self.host, self.port))
            self.cert = ssock.getpeercert()
            self.der = ssock.getpeercert(True)
            self.pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(True))
            self.version  = ssock.version()
            ssock.close()
            return True
        except socket.timeout:
            raise Exception
    #------------------------------#
    def cipherv13(self):
        try:
            all_scan_requests = [
                ServerScanRequest(server_location=ServerNetworkLocation(hostname=self.host)),
            ]
        except ServerHostnameCouldNotBeResolved:
            # Handle bad input ie. invalid hostnames
            print("Error resolving the supplied hostnames")
        scanner = Scanner()
        scanner.queue_scans(all_scan_requests)
        self.cipherv13s = []
        for result in scanner.get_results():
            tls1_3_attempt = result.scan_result.tls_1_3_cipher_suites
            if tls1_3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                print("TLS 1.3 cipher suite error")
            elif tls1_3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                self.tls1_3_results = tls1_3_attempt.result
                assert self.tls1_3_results 
                for accepted_cipher_suite in self.tls1_3_results.accepted_cipher_suites:
                    self.cipherv13s.append(accepted_cipher_suite.cipher_suite.name)
        self.Cipher_results = self.cipherv13s + self.Cipher_results
    #------------------------------#
    def check_proto(self):
        self.proto_check = []
        proto_list = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2] 
        proto_dict = {ssl.PROTOCOL_TLSv1:'TLSv1.0', ssl.PROTOCOL_TLSv1_1:'TLSv1.1', ssl.PROTOCOL_TLSv1_2:'TLSv1.2'}

        for proto in proto_list:
            try:
                ctx = ssl.SSLContext(proto)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssock = ctx.wrap_socket(sock,server_hostname=self.host)
                ssock.connect((self.host, self.port))
                ssock.close()
                self.proto_check.append(proto_dict[proto])
            except:
                continue
        if self.version == 'TLSv1.3':
            self.proto_check.append(self.version)
        self.proto_csv = ''
        for i in range(len(self.proto_check)):
            if not i==(len(self.proto_check)-1):
                self.proto_csv = self.proto_csv + self.proto_check[i] + ', '
            else:
                self.proto_csv = self.proto_csv + self.proto_check[i] 
    #------------------------------# 
    def proto_grade(self):
        proto_dict = {"TLSv1.3": 100, "TLSv1.2": 90, "TLSv1.1": 80, "TLSv1.0": 70, "SSLv2.3": 60,"UNKNOWN": 0}
        proto_values = []
        for proto in self.proto_check:
            proto_values.append(proto_dict.get(proto, 0))
        self.proto_Score = max(proto_values)
        if "TLSv1.0" in self.proto_check:
            self.proto_Score = self.proto_Score - 20
    #------------------------------#
    def cert_object(self):
        self.cert_obj = load_pem_x509_certificate(bytes(self.pem,'utf-8'))
        self.PKeySize = self.cert_obj.public_key().key_size
        self.sig=self.cert_obj.signature_algorithm_oid._name
    #------------------------------#
    def OCSP_status(self):
        self.status = ocspchecker.get_ocsp_status(self.host)  
        self.ocspstat = '' 
        if 'GOOD' in self.status[2]:
            self.ocspstat = 'GOOD'
        else:
            self.ocspstat = 'REVOKED'
    #------------------------------#
    def analyze_info(self):
        self.issuer = self.cert['issuer'][-1][0][-1]
        self.expiry_day = datetime.strptime(self.cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        self.serialNum = self.cert['serialNumber']
        self.sha1thumb = hashlib.sha1(self.der).hexdigest()
        self.sha256thumb = hashlib.sha256(self.der).hexdigest()
    #------------------------------# 
    def cert_grade(self):
        if ((self.expiry_day-self.now).days < 0):
            self.cert_Score = 0
        elif 'md5' in self.sig.lower() or 'sha1' in self.sig:
            self.cert_Score = 50
        else:
            self.cert_Score = 100
    #------------------------------#    
    def printanalyze(self):
        if not self.holi:
            print('\nCertificate Score: ' + str(self.cert_Score))
            print('Protocol Score: ' + str(self.proto_Score))
            print('Key Score: ' + str(self.bitPoint))
            print('Cipher Score: ' + str(self.ciphers_score) + '\n')
            # ====================================== #
            print('Overall Grade: ' + self.OverGrade + '\n')
            # ====================================== #
            print('Host name: ' + self.host)
            print('Issuer: ' + self.issuer)
            print('Expiry date: ' + str(self.expiry_day) + ' (' + str((self.expiry_day-self.now).days) + ' days from today)')
            print('Serial number: ' + self.serialNum)
            print('SHA1 thumbprint: ' + self.sha1thumb) 
            print('SHA256 thumbprint: ' + self.sha256thumb)
            print('Key length: ' + str(self.PKeySize))
            print('Signature Algorithm: ' + self.sig)
            self.print_proto()
            self.print_ocsp()
            self.print_cipher()
            return
        else:
            return [str(self.host), str(self.cert_Score), str(self.proto_Score), str(self.bitPoint), str(self.ciphers_score), str(self.OverGrade), self.issuer, self.serialNum, self.sha1thumb, self.sha256thumb, str(self.PKeySize), self.sig, self.ocspstat , str((self.expiry_day-self.now).days), self.proto_csv]   
    #------------------------------#
    def bit_grade(self):
        def roundup(a):
            return int(math.ceil(a / 10.0)) * 10
        keyType = {crypto.TYPE_RSA:'rsaEncryption', crypto.TYPE_DSA:'dsaEncryption', 408:'id-ecPublicKey'}
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, self.pem)
        type = keyType[x509.get_pubkey().type()]
        length = x509.get_pubkey().bits()
        if type in ['rsaEncryption', 'dsaEncryption']:
            bit_strength = (1/math.log(2))*(1.923*pow(length*math.log(2),1/3)*pow(math.log(length*math.log(2)),2/3)-4.69)
        else:
            bit_strength = length/2
        self.bitPoint=min(100,roundup(bit_strength))
    #------------------------------#    
    def print_proto(self):
        print('Supported protocols:')
        for protocol in self.proto_check:
            print('\t' + protocol)
    #------------------------------# 
    def cipher_grade(self):
        with open('ciphers.json', 'r') as read:
            cipher_read = json.load(read)
        scores = {}
        for cipher in self.Cipher_results:
            scores[cipher] = cipher_read[cipher] if cipher in cipher_read else 0
        self.ciphers_score = max([v for k, v in scores.items()]) if self.Cipher_results else 0
    #------------------------------#
    def print_cipher(self):
        # self.Cipher_results = self.cipherv13s + self.Cipher_results
        print(str(len(self.Cipher_results))+'/145 ciphers found:')
        for cipher in self.Cipher_results:
            print('\t' + str(cipher))
    #------------------------------#
    def print_ocsp(self):
        print('OCSP status:')
        for i_stat in range(1,3):
            print('\t' + self.status[i_stat])
        
    #------------------------------#
    def analyze_all(self):
        self.get_cert()
        self.Cipher_results = self.get_cipher_list()
        self.OCSP_status()
        self.analyze_info()
        self.cert_object()
        self.check_proto()
        self.cert_grade()
        self.cipherv13()
        self.bit_grade()
        self.cipher_grade()
        self.proto_grade()
        self.Overall()
        return self.printanalyze() 
    #------------------------------#
    def Overall(self):
        self.Total = self.cert_Score + self.proto_Score + self.bitPoint + self.ciphers_score
        if self.Total >= 380:
            self.OverGrade = 'A+'
        elif self.Total >= 360:
            self.OverGrade = 'A'
        elif self.Total >= 340:
            self.OverGrade = 'B'
        elif self.Total >= 320:
            self.OverGrade = 'C'
        elif self.Total >= 300:
            self.OverGrade = 'D'
        else:
            self.OverGrade = 'E'
    #------------------------------#
    def get_cipher_list(self):
        Cipher_results = []
        for CIPHERS in self.CIPHERS_list:
            try:
                session = requests.session()
                adapter = TlsAdapter(ssl.OP_NO_TLSv1_3, CIPHERS)
                session.mount("https://", adapter)
                r = session.request('GET', 'https://' + self.host, timeout=0.5)
                if 'Response' in str(r):
                    Cipher_results.append(CIPHERS)
            except:
                continue
        return Cipher_results
    #------------------------------#
    def saving_header(self):
        return ['Domain', 'Certificate Score', 'Protocol Score', 'Key Score', 'Cipher Score', 'Overall Grade', 'Issuer', 'Serial Number', 'SHA-1 Thumbprint', 'SHA-256 Thumbprint', 'Key Length', 'Signature Algorithm', 'OCSP Status', 'Days before expiring', 'Support Protocols']
    #------------------------------#
    def analyze_host_check(self, host_name, save_file_csv):
        data_check = pd.read_csv(save_file_csv, index_col=False)
        check_host = data_check['Domain'].tolist()
        if host_name in check_host:
            return True
        return False
    #------------------------------#
    def handle(self, save_file_csv):
        if not self.holi:
                self.analyze_all()
        else:
            csv_file = open(save_file_csv, 'a', encoding='UTF8')
            writer = csv.writer(csv_file)
            num_row = len(list(csv.reader(open(save_file_csv, 'r+', encoding='UTF8'))))
            if num_row == 0:
                writer.writerow(self.saving_header())
            
            for i, host in enumerate(self.read):
                print("{}/{} - current domain: {}".format(i+1, len(self.read), host))
                try:
                    if (num_row == 0) or (not self.analyze_host_check(host, save_file_csv)):
                        self.host = host
                        host_result = self.analyze_all()
                        writer.writerow(host_result)
                        print('Done!!!!')
                        csv_file.flush()
                except KeyboardInterrupt:
                    print('Force skip!!!!')
                    continue
                except Exception:
                    print('Passed!!!!')
                    continue 
                
            csv_file.close()  
#++++++++++++++++++++++++++++++++++# 
class TlsAdapter(HTTPAdapter):

    def __init__(self, ssl_options=0, CIPHERS=None, **kwargs):
        self.ssl_options = ssl_options
        self.CIPHERS = CIPHERS
        super(TlsAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        ctx = ssl_.create_urllib3_context(ciphers=self.CIPHERS, cert_reqs=ssl.CERT_REQUIRED, options=self.ssl_options)
        self.poolmanager = PoolManager(*pool_args,
                                       ssl_context=ctx,
                                       **pool_kwargs)
#++++++++++++++++++++++++++++++++++# 
if __name__ == '__main__':
    begin = time.time()
    cert = analyzeCertificate(args.host, args.port, args.holi, CIPHERS_list)
    cert.handle(args.save_path_csv)
    print("Total time: {}".format(time.time()-begin))
   
    