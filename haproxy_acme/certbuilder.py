from haproxy_acme.csr import create_csr_ec
from haproxy_acme.private import make_private_key_ec


def generate_cert(country, state, locality, organisation, domains):
    key = make_private_key_ec()
    csr = create_csr_ec(key, country, state, locality, organisation, domains)

    return key, csr