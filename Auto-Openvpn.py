#!/usr/bin/env python

import os
import socket
from OpenSSL import crypto, SSL



# Crée une clé RSA avec le nombre de bits spécifié.

# create an RSA key with the specified number of bits.
def create_key(algorithm=crypto.TYPE_RSA, numbits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, numbits)
    return pkey

# Crée un certificat et une demande de signature de celui-ci avec les attributs spécifiés ci-dessous
# Changez les attributs pour correspondre à vos besoin.

# Creates a certificate signing request with the specified subject attributes.
# Change the specified subject attributes to fit your needs.
def create_cert(pkey, CN, C=None, ST=None, L=None, O=None, OU=None, EmailAddress=None, hashalgorithm='sha256WithRSAEncryption'):
    req = crypto.X509Req()
    req.get_subject()
    subj = req.get_subject()

    if C:
        subj.C = C
    if ST:
        subj.ST = ST
    if L:
        subj.L = L
    if O:
        subj.O = O
    if OU:
        subj.OU = OU
    if CN:
        subj.CN = CN
    if EmailAddress:
        subj.emailAddress = EmailAddress

    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req
