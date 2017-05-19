from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def make_private_key_ec():
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return key


def make_private_key_rsa(size=2048):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend())
    return key
