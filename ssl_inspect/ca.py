"""
Root CA generation and metadata management.

The CA private key is written to ssl/mitm-conf/mitmproxy-ca.pem — the
file mitmproxy natively reads. We do NOT store the private key in MySQL;
the DB only holds public metadata for display in the web UI. If an
attacker dumps the DB, they get nothing that can forge certs.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from logging_config import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONF_DIR = REPO_ROOT / "ssl" / "mitm-conf"
CA_COMBINED_PATH = CONF_DIR / "mitmproxy-ca.pem"        # key + cert, mitmproxy reads this
CA_CERT_PATH = CONF_DIR / "mitmproxy-ca-cert.pem"        # public cert, for client install

DEFAULT_CN = "Enterprise AI IDS Root CA"
DEFAULT_VALIDITY_DAYS = 3650


def ca_exists() -> bool:
    return CA_COMBINED_PATH.is_file() and CA_CERT_PATH.is_file()


def ensure_ca() -> x509.Certificate:
    """Generate the CA if missing, and always sync its metadata to MySQL."""
    if ca_exists():
        try:
            cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
            _sync_metadata(cert)
            return cert
        except Exception:
            logger.error("CA cert corrupt; regenerating", exc_info=True)

    return generate_ca()


def generate_ca(
    common_name: str = DEFAULT_CN,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> x509.Certificate:
    """Generate a fresh root CA and write it to the mitmproxy conf dir."""
    logger.warning("Generating new root CA: CN=%s", common_name)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise AI IDS"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Network Security"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    CONF_DIR.mkdir(parents=True, exist_ok=True)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    CA_COMBINED_PATH.write_bytes(cert_pem + key_pem)
    CA_CERT_PATH.write_bytes(cert_pem)

    try:
        CONF_DIR.chmod(0o700)
        CA_COMBINED_PATH.chmod(0o600)   # private key — restrictive
        CA_CERT_PATH.chmod(0o644)       # public — installable
    except OSError:
        pass

    _sync_metadata(cert)
    logger.info("Root CA written to %s", CA_COMBINED_PATH)
    return cert


def _sync_metadata(cert: x509.Certificate) -> None:
    """Persist CA public metadata to MySQL for the web UI to read."""
    try:
        from storage.db import get_session
        from storage.models import SslConfig

        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attr[0].value if cn_attr else DEFAULT_CN
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        session = get_session()
        try:
            row = session.get(SslConfig, 1)
            if row is None:
                row = SslConfig(id=1, ca_common_name=cn)
                session.add(row)
            row.ca_common_name = cn
            row.ca_serial_hex = format(cert.serial_number, "x")
            row.ca_not_before = not_before
            row.ca_not_after = not_after
            row.ca_fingerprint_sha256 = fp
            session.commit()
        finally:
            session.close()
    except Exception:
        logger.error("Failed to sync CA metadata to MySQL", exc_info=True)


def read_ca_cert_pem() -> bytes:
    return CA_CERT_PATH.read_bytes()


def delete_ca() -> None:
    """Wipe the CA from disk. mitmproxy will regenerate on next start."""
    for p in (CA_COMBINED_PATH, CA_CERT_PATH):
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass