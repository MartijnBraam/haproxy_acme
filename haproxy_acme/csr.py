from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def make_csr(key, country, state, locality, organisation, domains):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ]))

    names = []
    for domain in domains:
        names.append(x509.DNSName(domain))

    csr = csr.add_extension(
        x509.SubjectAlternativeName(names),
        critical=False,
    )

    return csr.sign(key, hashes.SHA256(), default_backend())
