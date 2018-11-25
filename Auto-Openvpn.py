import os
import sys
import subprocess
from OpenSSL import crypto, SSL


# OpenVPN is fairly simple since it works on OpenSSL. The OpenVPN server contains
# a root certificate authority that can sign sub-certificates. The certificates
# have very little or no information on who they belong to besides a filename
# and any required information. Everything else is omitted or blank.
# The client certificate and private key are inserted into the .ovpn file
# which contains the OpenVPN settings as well and the entire thing is then ready for
# the user.
# EasyRSA generates a standard unsigned certificate, certificate request, and private key.
# It then signs the certificate against the CA then dumps the certificate request in the trash.
# The now signed certificate and private key are returned.


#   Change this if you want to use a different size for DH_PARAMS
DH_SIZE = 2048

#   Create a default .conf file for OpenVPN
#   Change [remote] and [port] to fit your needs 
def config_file_generator():

    server_conf_file = {}
    client_conf_file = {}

    server_conf_file['remote'] = ("10.0.2.1")
    server_conf_file['port'] = ("1194")
    server_conf_file['proto'] = ("udp")
    server_conf_file['dev'] = ("tun\n")
    server_conf_file['float'] = (" ")
    server_conf_file['ifconfig'] = ("194.0.0.1 194.0.0.2")
    server_conf_file['route'] = ("10.0.2.0 255.255.255.0")
    server_conf_file['script-security'] = ("1")
    server_conf_file['keepalive'] = ("10 120")
    server_conf_file['cipher'] = ("AES-256-CBC")
    server_conf_file['tls-server'] = (" ")
    server_conf_file['persist-key'] = (" ")
    server_conf_file['persist-tun'] = (" ")
    server_conf_file['persist-remote-ip'] = (" ")
    server_conf_file['persist-local-ip'] = (" ")
    server_conf_file['user'] = ("nobody")
    server_conf_file['group'] = ("nogroup")
    server_conf_file['key-direction'] = ("0")

    client_conf_file['remote'] = ("10.0.1.1")
    client_conf_file['port'] = ("1194")
    client_conf_file['proto'] = ("udp")
    client_conf_file['dev'] = ("tun")
    client_conf_file['float'] = (" ")
    client_conf_file['ifconfig'] = ("194.0.0.2 194.0.0.1")
    client_conf_file['route'] = ("10.0.1.0 255.255.255.0")
    client_conf_file['script-security'] = ("1")
    client_conf_file['keepalive'] = ("10 120")
    client_conf_file['cipher'] = ("AES-256-CBC")
    client_conf_file['tls-client'] = (" ")
    client_conf_file['persist-key'] = (" ")
    client_conf_file['persist-tun'] = (" ")
    client_conf_file['persist-remote-ip'] = (" ")
    client_conf_file['persist-local-ip'] = (" ")
    client_conf_file['user'] = ("nobody")
    client_conf_file['group'] = ("nogroup")
    client_conf_file['key-direction'] = ("1")

    return server_conf_file, client_conf_file

#   Create four dict who contains the values needed to create CA and certs
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

#   generates a key needed for the CA and Certs of generate_ca() and generate_certificate()
def create_key(size):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, size)
    return key

#   Generates a CA certificate and fill it with the values contained in dict
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

#   generates a Cert certificate and fill it with the values contained in dict.
#   Arguments are filled in build_cert()
def generate_certificate(certificate_dict, ca, cakey, name):

#   Generate the private key the size contained in dict
    key = create_key(certificate_dict['keyfilesize'])

#   Generate the certificate request and fill informations with dict
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

#   Set valid time for the certificate
    if 'validfrom' in certificate_dict:
        cert.set_notBefore(certificate_dict['validfrom'])
    if 'validto' in certificate_dict:
        cert.set_notAfter(certificate_dict['validto'])

#   Define cert type depending if it is for client or server.
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

#   First check if file already exist. If not, create them.
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
#   First generate the certificate and then create the certfile + certkey
def build_cert(config_certificate, ca_cert, ca_key, name):
    cert_req, cert_cert, cert_key = generate_certificate(
        config_certificate, ca_cert, ca_key, name)
    open(config_certificate['cert_filename'], "w").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert_cert))
    open(config_certificate['cert_key'], "w").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key))
    return cert_cert, cert_key

#   Generates a Diffie-Hellman key using the size of DH_size and a TLS key (ta.key)
def gen_dh_tlsauth():
    run(['openvpn', '--genkey', '--secret', 'ta.key'])

    run(['openssl', 'dhparam', '-out', 'dh' +
         str(DH_SIZE)+'.pem', str(DH_SIZE)])

#   Create Only one file with all the informations in it.
#   used to create a unique .ovpn file containing all the CA, Cert, and private keys needed.
def Create_ovpn(filename):
    with open(filename) as f:
        data = f.read()
    return (data)

#   main function
if __name__ == "__main__":

#   Build the dicts needed to create CA and Cert
    config_server_ca, config_server_cert, config_client_ca, config_client_cert = config_creator()

#   Build the Server and Client CA
    server_ca_cert, server_ca_key = build_ca(config_server_ca, 'Server')
    client_ca_cert, client_ca_key = build_ca(config_client_ca, 'Client')
    print("CA OK")

#   Build the server and client certificate (signed by the above CAs)
    build_cert(config_server_cert, server_ca_cert, server_ca_key, 'Server')
    build_cert(config_client_cert, client_ca_cert, client_ca_key, 'Client')
    print("CERT OK")

#   Generate Diffie Hellman key and TLS key
    gen_dh_tlsauth()
    print("DH OK")

#   Build the dict containing the OpenVPN configuration files
    server_config_file, client_config_file = config_file_generator()

#   build the server configuration file (serverVPN.conf)
    with open('serverVPN.conf', 'w') as sc:
        for k, v in server_config_file.items():
            sc.write('{}'.format(k) + ' ' + '{}'.format(v) + '\n')

#   Build the client configuration file (clientVPN.conf)
    with open('clientVPN.conf', 'w') as cc:
        for x, y in client_config_file.items():
            cc.write('{}'.format(x) + ' ' + '{}'.format(y) + '\n')

#   Gather all CA, Cert, Private keys and conf in one file for the Server
    server_conf = Create_ovpn("serverVPN.conf")
    server_ca = Create_ovpn("server_ca.pem")
    server_cert = Create_ovpn("server_cert.pem")
    server_key = Create_ovpn("server_cert.key")
    server_ta = Create_ovpn("ta.key")
    server_dh = Create_ovpn("dh"+str(DH_SIZE)+".pem")

#   Gather all CA, Cert, Private keys and conf in one file for the Client
    client_conf = Create_ovpn("clientVPN.conf")
    client_ca = Create_ovpn("client_ca.pem")
    client_cert = Create_ovpn("client_cert.pem")
    client_key = Create_ovpn("client_cert.key")
    client_ta = Create_ovpn("ta.key")

#   Fill the .ovpn file with the CA, cert, Private key and conf above.
    server_ovpn = "%s<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n<dh>\n%s</dh>\n<tls-crypt>\n%s</tls-crypt>" % (
        server_conf, client_ca, server_cert, server_key, server_dh, server_ta)
    client_ovpn = "%s<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n<tls-crypt>\n%s</tls-crypt>" % (
        client_conf, server_ca, client_cert, client_key, server_ta)

#   write server.ovpn file and client.ovpn file
    f = open("server.ovpn", "w")
    f.write(server_ovpn)
    j = open("client.ovpn", "w")
    j.write(client_ovpn)

#   remove all files after .ovpn files created
    os.remove("client_ca.key")
    os.remove("client_ca.pem")
    os.remove("client_cert.key")
    os.remove("client_cert.pem")
    os.remove("clientVPN.conf")
    os.remove("dh"+str(DH_SIZE)+".pem")
    os.remove("server_ca.key")
    os.remove("server_ca.pem")
    os.remove("server_cert.key")
    os.remove("server_cert.pem")
    os.remove("serverVPN.conf")
    os.remove("ta.key")
    print("OPENVPN SUCCESFULLY CONFIGURED")
    
#   Ask user if they want to use scp to transfer clientfile
    transfer = raw_input(
        "do you want to transfer the clientfile to client via scp ? (yes/no)")

#   If yes then start scp to client
#   If no exit
    if transfer == 'yes':
        local_user = raw_input("Enter your local username : ")
        yourip = client_config_file['remote']
        user = raw_input("Enter server username : ")
        server = server_config_file['remote']
        os.system("scp" + " " + local_user + "@" + yourip + ":" +
                  " " + "client.ovpn" + " " + user + "@" + server + ":")
        if transfer == 'no':
            sys.exit(0)
    sys.exit(0)
