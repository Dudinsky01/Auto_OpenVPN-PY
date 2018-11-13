import os
import sys
import tarfile
import subprocess
from OpenSSL import crypto, SSL

#   Change this if you want to use a different size for DH_PARAMS
DH_SIZE = 2048

#   Create four dict with the values needed to create CA and certs
def config_creator():
    server_ca = {}
    server_cert = {}
    client_ca = {}
    client_cert = {}

#   Server Certification Authority
    server_ca['commonName'] = "Server CA"
    server_ca['cert_filename'] = "server_ca.pem"
    server_ca['cert_key'] = "server_ca.key"
    server_ca['serial'] = 12345999
    server_ca['validfrom'] = "20180101000000Z"
    server_ca['validto'] = "20200101000000Z"
    server_ca['keyfilesize'] = 4096
    server_ca['hashalgorithm'] = "sha512"

#   Server Certificate (signed by the CA above)
    server_cert['commonName'] = "Server Cert"
    server_cert['cert_filename'] = "server_cert.pem"
    server_cert['cert_key'] = "server_cert.key"
    server_cert['serial'] = 12345888
    server_cert['validfrom'] = "20180101000000Z"
    server_cert['validto'] = "20200101000000Z"
    server_cert['keyfilesize'] = 4096
    server_cert['hashalgorithm'] = "sha512"

#   Client Certification Authority
    client_ca['commonName'] = "Client CA"
    client_ca['cert_filename'] = "client_ca.pem"
    client_ca['cert_key'] = "client_ca.key"
    client_ca['serial'] = 12345777
    client_ca['validfrom'] = "20180101000000Z"
    client_ca['validto'] = "20200101000000Z"
    client_ca['keyfilesize'] = 4096
    client_ca['hashalgorithm'] = "sha512"

#   Client Certificate (signed by the CA above)
    client_cert['commonName'] = "Client Cert"
    client_cert['cert_filename'] = "client_cert.pem"
    client_cert['cert_key'] = "client_cert.key"
    client_cert['serial'] = 12345666
    client_cert['validfrom'] = "20180101000000Z"
    client_cert['validto'] = "20200101000000Z"
    client_cert['keyfilesize'] = 4096
    client_cert['hashalgorithm'] = "sha512"

    return server_ca, server_cert, client_ca, client_cert


#   generates a key for the CA and Certs of generate_ca() and generate_certificate()
def generate_key(size):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, size)
    return key
