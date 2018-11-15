import os
import sys
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

#   a simple run command use for the gen_dh_tlsauth()
def run(cmd):
    subprocess.Popen(cmd).wait()

#   generates a key for the CA and Certs of generate_ca() and generate_certificate()
def create_key(size):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, size)
    return key

#   Generates a CA certificate
def generate_ca(ca_dict):
    ca = crypto.X509()
    ca.set_version(2)
    ca.set_serial_number(ca_dict['serial'])
    ca_subj = ca.get_subject()
    if 'commonName' in ca_dict:
        ca_subj.commonName = ca_dict['commonName']
    if 'stateOrProvinceName' in ca_dict:
        ca_subj.stateOrProvinceName = ca_dict['stateOrProvinceName']
    if 'localityName' in ca_dict:
        ca_subj.localityName = ca_dict['localityName']
    if 'organizationName' in ca_dict:
        ca_subj.organizationName = ca_dict['organizationName']
    if 'organizationalUnitName' in ca_dict:
        ca_subj.organizationalUnitName = ca_dict['organizationalUnitName']
    if 'emailAddress' in ca_dict:
        ca_subj.emailAddress = ca_dict['emailAddress']
    if 'countryName' in ca_dict:
        ca_subj.countryName = ca_dict['countryName']
    if 'validfrom' in ca_dict:
        ca.set_notBefore(ca_dict['validfrom'])
    if 'validto' in ca_dict:
        ca.set_notAfter(ca_dict['validto'])
    key = create_key(ca_dict['keyfilesize'])

    ca.add_extensions([
        crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
        crypto.X509Extension("keyUsage", False, "keyCertSign, cRLSign"),
        crypto.X509Extension("subjectKeyIdentifier",
                             False, "hash", subject=ca),
    ])

    ca.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier",
                             False, "keyid:always", issuer=ca)
    ])

    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.sign(key, ca_dict['hashalgorithm'])
    return ca, key

#   generates a Cert certificate
def generate_certificate(certificate_dict, ca, cakey, name):

#   Generate the private key
    key = create_key(certificate_dict['keyfilesize'])

#   Generate the certificate request
    req = crypto.X509Req()
    req_subj = req.get_subject()
    if 'commonName' in certificate_dict:
        req_subj.commonName = certificate_dict['commonName']
    if 'stateOrProvinceName' in certificate_dict:
        req_subj.stateOrProvinceName = certificate_dict['stateOrProvinceName']
    if 'localityName' in certificate_dict:
        req_subj.localityName = certificate_dict['localityName']
    if 'organizationName' in certificate_dict:
        req_subj.organizationName = certificate_dict['organizationName']
    if 'organizationalUnitName' in certificate_dict:
        req_subj.organizationalUnitName = certificate_dict['organizationalUnitName']
    if 'emailAddress' in certificate_dict:
        req_subj.emailAddress = certificate_dict['emailAddress']
    if 'countryName' in certificate_dict:
        req_subj.countryName = certificate_dict['countryName']

    req.set_pubkey(key)
    req.sign(key, certificate_dict['hashalgorithm'])

#   Now generate the certificate itself
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(certificate_dict['serial'])
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.set_issuer(ca.get_subject())

    if 'validfrom' in certificate_dict:
        cert.set_notBefore(certificate_dict['validfrom'])
    if 'validto' in certificate_dict:
        cert.set_notAfter(certificate_dict['validto'])

    if name == 'client':
        usage = 'clientAuth'
        nscerttype = 'client'
    elif name == 'server':
        usage = 'serverAuth'
        nscerttype = 'server'

    cert.add_extensions([
        crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
        crypto.X509Extension(
            "keyUsage", False, "digitalSignature,keyAgreement"),
        crypto.X509Extension("extendedKeyUsage", False, usage),
        crypto.X509Extension("nsCertType", False, nscerttype),
        crypto.X509Extension("subjectKeyIdentifier",
                             False, "hash", subject=cert),
        crypto.X509Extension("authorityKeyIdentifier",
                             False, "keyid:always", issuer=ca)
    ])

    cert.sign(cakey, certificate_dict['hashalgorithm'])
    return req, cert, key

#   build the CA certificate
def build_ca(server_ca, name):
    if os.path.isfile(server_ca['cert_filename']) and os.path.isfile(server_ca['cert_key']):
        ca_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(server_ca['cert_filename']).read())
        ca_key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(server_ca['cert_key']).read())
    else:
        ca_cert, ca_key = generate_ca(server_ca)
        open(server_ca['cert_filename'], "w").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
        open(server_ca['cert_key'], "w").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
    return ca_cert, ca_key

#   build the Cert certificate
def build_cert(config_certificate, ca_cert, ca_key, name):
    cert_req, cert_cert, cert_key = generate_certificate(
        config_certificate, ca_cert, ca_key, name)
    open(config_certificate['cert_filename'], "w").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert_cert))
    open(config_certificate['cert_key'], "w").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key))
    return cert_cert, cert_key

#   Generates a Diffie-Hellman key and a TLS key
def gen_dh_tlsauth():
    run(['openvpn', '--genkey', '--secret', 'ta.key'])

    run(['openssl', 'dhparam', '-out', 'dh' +
         str(DH_SIZE)+'.pem', str(DH_SIZE)])

#   Create Only one file with all the informations in
def Create_ovpn(filename):
    with open(filename) as f:
        data = f.read()
    return (data)
