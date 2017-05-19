from cryptography.hazmat.primitives import serialization


def write_pem(path, data):
    with open(path, 'wb') as handle:
        if hasattr(data, 'private_bytes'):
            key = data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            handle.write(key)
