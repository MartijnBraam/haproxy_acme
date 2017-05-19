import base64
import json

import copy
import requests
import struct

from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1, PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256

nonce = None
server = None
key = None

_account = None


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
    global nonce

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


def register(email):
    global _account
    url = server + "/acme/new-reg"
    response = _acme_request_signed(url, {
        "resource": "new-reg",
        "terms-of-service-agreed": True,
        "contact": [
            "mailto:{}".format(email)
        ]
    })
    _account = response.headers['location']
