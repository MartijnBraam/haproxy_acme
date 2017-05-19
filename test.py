from cryptography.hazmat.primitives import serialization

from haproxy_acme.certbuilder import generate_cert

key, csr = generate_cert('NL', 'Drenthe', 'Smilde', 'BrixIT', ['brixit.nl', 'blog.brixit.nl', 'www.brixit.nl'])

print(key)
print(csr)

with open("/workspace/test.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
