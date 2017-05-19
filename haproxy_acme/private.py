from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def make_private_key_ec():
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return key
