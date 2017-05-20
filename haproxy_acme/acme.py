import base64
import hashlib
import json

import copy
import os
from time import sleep

import requests
import struct

from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1, PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256

from haproxy_acme.certbuilder import generate_cert
from haproxy_acme.challenges.http01 import process_http01_challenge
from haproxy_acme.csr import to_der
from haproxy_acme.writer import write_pem

nonce = None
server = None
key = None

_account = None
_thumbprint = None


def _b64(data):
    return base64.urlsafe_b64encode(data).decode('utf8').replace("=", "")


def _long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def _long_to_base64(n):
    bys = _long2intarr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")


def _acme_request_signed(url, payload):
    global nonce, _thumbprint

    if nonce is None:
        directory_url = server + "/directory"
        response = requests.get(directory_url)
        nonce = response.headers['Replay-Nonce']

    payload = json.dumps(payload).encode('utf8')
    payload = _b64(payload)
    private_numbers = key.private_numbers()
    exponent = private_numbers.public_numbers.e
    modulus = private_numbers.public_numbers.n

    header = {
        "alg": "RS256",
        "jwk": {
            "e": _long_to_base64(exponent),
            "kty": "RSA",
            "n": _long_to_base64(modulus),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    _thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
    header['nonce'] = nonce
    header['url'] = url
    protected = _b64(json.dumps(header).encode('utf8'))
    signer = key.signer(PKCS1v15(), SHA256())
    signer.update("{}.{}".format(protected, payload).encode("utf-8"))
    digest = signer.finalize()
    jws = {
        "protected": protected,
        "payload": payload,
        "signature": _b64(digest)
    }
    response = requests.post(url, json=jws, headers={
        'Content-Type': 'application/jose+json'
    })
    nonce = response.headers['Replay-Nonce']
    return response


def register(email, agreement):
    global _account
    url = server + "/acme/new-reg"
    response = _acme_request_signed(url, {
        "resource": "new-reg",
        "terms-of-service-agreed": True,
        "agreement": agreement,
        "contact": [
            "mailto:{}".format(email)
        ]
    })
    _account = response.headers['location']


def _check_verification(response):
    return response.json()['status'] == 'pending'


def verify_domain(subjects, verify_directory, key_directory, dsn):
    dsn['domains'] = subjects

    key_prefix = os.path.join(key_directory, 'private', '{}.key'.format(subjects[0]))
    csr_prefix = os.path.join(key_directory, 'csr', '{}.csr'.format(subjects[0]))
    crt_prefix = os.path.join(key_directory, 'live', '{}.crt'.format(subjects[0]))

    if os.path.isfile("{}.rsa".format(key_prefix)):
        dsn['key'] = key_prefix

    (key_ec, csr_ec), (key_rsa, csr_rsa) = generate_cert(**dsn)

    write_pem("{}.rsa".format(key_prefix), key_rsa)
    write_pem("{}.ecdsa".format(key_prefix), key_ec)

    write_pem("{}.rsa".format(csr_prefix), csr_rsa)
    write_pem("{}.ecdsa".format(csr_prefix), csr_ec)

    url = server + '/acme/new-authz'
    response = _acme_request_signed(url, {
        'resource': 'new-authz',
        'identifier': {
            "type": "dns",
            "value": subjects[0]
        }
    }).json()

    challenge = [c for c in response['challenges'] if c['type'] == 'http-01'][0]
    keyauth = process_http01_challenge(challenge, _thumbprint, verify_directory)

    url = challenge['uri']
    response = _acme_request_signed(url, {
        'resource': 'challenge',
        'keyAuthorization': keyauth
    })
    pending = _check_verification(response)

    while pending:
        sleep(1)
        response = requests.get(url)
        pending = _check_verification(response)

    url = server + '/acme/new-cert'

    response = _acme_request_signed(url, {
        'resource': 'new-cert',
        'csr': _b64(to_der(csr_rsa))
    })

    print(json.dumps(response.headers))

    cert_file = "{}.rsa".format(crt_prefix)
    write_pem(cert_file, response.content, append="{}.rsa".format(key_prefix))

    response = _acme_request_signed(url, {
        'resource': 'new-cert',
        'csr': _b64(to_der(csr_ec))
    })

    cert_file = "{}.ecdsa".format(crt_prefix)
    write_pem(cert_file, response.content, append="{}.ecdsa".format(key_prefix))
