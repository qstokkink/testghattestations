from binascii import unhexlify

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from sigstore import dsse
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify import policy, Verifier
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm


def read_attestation() -> bytes:
    with open("TODO.sigstore.json", "rb") as fp:  # TODO: Determine file
        bundle_bytes = fp.read()

    subject_digest = "sha256:c5e97e7fc5c75af103fd77d70317a14ae12e23f6be297de8cb8524c9f9253381" # TODO: same as file??
    bundle = Bundle.from_json(bundle_bytes)
    verifier = Verifier.production()
    policy_ = policy.Identity(
        identity="https://github.com/qstokkink/testghattestations/.github/workflows/build.yml@refs/heads/main",
        issuer="https://token.actions.githubusercontent.com"
    )
    type_, payload = verifier.verify_dsse(bundle=bundle, policy=policy_)

    if type_ != dsse.Envelope._TYPE:
        raise RuntimeError(f"expected JSON payload for DSSE, got {type_}")

    stmt = dsse.Statement(payload)
    digest = Hashed(
        digest=unhexlify("c5e97e7fc5c75af103fd77d70317a14ae12e23f6be297de8cb8524c9f9253381"),
        algorithm=HashAlgorithm.SHA2_256
    )

    if not stmt._matches_digest(digest):
        raise RuntimeError("in-toto statement has no subject for digest")

    signer = bundle.signing_certificate.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    cert = bundle._inner.verification_material.certificate.raw_bytes

    print("Signer public key:", signer)
    print("Cert:", cert)

    return  cert

if __name__ == "__main__":
    cert = read_attestation()  # x509/DER format not PKCS12

    with open("cert.der", "wb") as handle:
        handle.write(cert)
