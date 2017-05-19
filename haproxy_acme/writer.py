from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


def write_pem(path, data):
    with open(path, 'wb') as handle:
        if hasattr(data, 'private_bytes'):
            key = data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            handle.write(key)


def read_pem(path):
    with open(path) as handle:
        data = handle.read()
    if 'PRIVATE KEY' in data:
        return load_pem_private_key(data, None, default_backend())
