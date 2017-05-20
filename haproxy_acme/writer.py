import base64
import textwrap

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend


def write_pem(path, data, append=None):
    with open(path, 'wb') as handle:
        if hasattr(data, 'private_bytes'):
            key = data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            handle.write(key)
        elif hasattr(data, 'public_bytes'):
            cert = data.public_bytes(serialization.Encoding.PEM)
            handle.write(cert)
        elif isinstance(data, bytes):
            cert = "\n".join(textwrap.wrap(base64.b64encode(data).decode('utf8'), 64))
            cert = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n".format(cert)
            if append is not None:
                for ak in append:
                    with open(ak) as appendfile:
                        cert += appendfile.read()
            handle.write(cert.encode('utf-8'))


def read_pem(path):
    with open(path, 'rb') as handle:
        data = handle.read()
    if b'BEGIN CERTIFICATE' in data:
        if b'PRIVATE KEY' in data:
            parts = data.split(b'-----END CERTIFICATE-----')
            data = parts[0] + b'-----END CERTIFICATE-----\n'
        print(data)
        return load_pem_public_key(data, default_backend())
    elif b'PRIVATE KEY' in data:
        return load_pem_private_key(data, None, default_backend())
