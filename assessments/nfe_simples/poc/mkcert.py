"""Gera um .pfx de teste (auto-assinado) com AIA CA_ISSUERS controlado."""
import sys, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

aia_url = sys.argv[1] if len(sys.argv) > 1 else None
out = sys.argv[2] if len(sys.argv) > 2 else "test.pfx"
pwd = b"senha123"

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"EMPRESA TESTE:12345678000199")])
now = datetime.datetime.now(datetime.timezone.utc)
b = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
     .public_key(key.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(days=1))
     .not_valid_after(now + datetime.timedelta(days=365)))
if aia_url:
    b = b.add_extension(x509.AuthorityInformationAccess([
        x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                               x509.UniformResourceIdentifier(aia_url))]), critical=False)
cert = b.sign(key, hashes.SHA256())
data = pkcs12.serialize_key_and_certificates(
    b"teste", key, cert, None, serialization.BestAvailableEncryption(pwd))
open(out, "wb").write(data)
print(f"escrito {out} (aia={aia_url})")
