from haproxy_acme.csr import make_csr
from haproxy_acme.private import make_private_key_ec, make_private_key_rsa


def generate_cert(country, state, locality, organisation, domains):
    key_ec = make_private_key_ec()
    key_rsa = make_private_key_rsa()

    csr_ec = make_csr(key_ec, country, state, locality, organisation, domains)
    csr_rsa = make_csr(key_rsa, country, state, locality, organisation, domains)

    return (key_ec, csr_ec), (key_rsa, csr_rsa)
