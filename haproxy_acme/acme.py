import base64
import json

import binascii
import requests


def _b64(data):
    return base64.urlsafe_b64encode(data).decode('utf8').replace("=", "")


def _acme_request_signed(url, payload, key):
    payload = json.dumps(payload).encode('utf8')
    payload = _b64(payload)



    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }


def acme_register(server, csr):
    url = server + "/acme/new-reg"
