"""
Root CA generation and metadata management.

The combined CA (cert + key) is written to ssl_inspect/conf/ids-ca.pem.
The public cert (for client installation) is written to
ssl_inspect/conf/ids-ca-cert.pem. The TLS interceptor (sslsplit) is given
separate cert and key files, produced from the combined PEM by
export_for_sslsplit().

The private key is never persisted in MySQL; the database holds only
public metadata (common name, serial, validity window, SHA-256
fingerprint) for display in the web UI. A database dump alone therefore
cannot be used to forge certificates.
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
CONF_DIR = REPO_ROOT / "ssl_inspect" / "conf"

# Combined cert + key (PEM bundle). Kept as a single file so the CA can be
# distributed as one artifact if needed; the split form is derived from it.
CA_COMBINED_PATH = CONF_DIR / "ids-ca.pem"

# Public cert, served to clients through /ssl/api/ca/cert.pem.
CA_CERT_PATH = CONF_DIR / "ids-ca-cert.pem"

# Split cert/key for sslsplit (-c / -k). Written by export_for_sslsplit().
SSLSplit_CERT_PATH = CONF_DIR / "sslsplit-ca.crt"
SSLSplit_KEY_PATH = CONF_DIR / "sslsplit-ca.key"

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
    """Generate a fresh root CA and write it to the CA config directory."""
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
        # .not_valid_before_utc / .not_valid_after_utc were added in
        # cryptography 42.0. The naive accessors (.not_valid_before /
        # .not_valid_after) are deprecated in the same release but still
        # present as of cryptography 44.x, so this fallback keeps the
        # code working on both older and newer installs.
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

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
    """Wipe the CA from disk. It will be regenerated on next start."""
    for p in (CA_COMBINED_PATH, CA_CERT_PATH, SSLSplit_CERT_PATH, SSLSplit_KEY_PATH):
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass


def export_for_sslsplit() -> tuple[Path, Path]:
    """
    Split the combined PEM into separate cert and key files, which is
    what sslsplit expects (-c <cert> -k <key>). Called automatically by
    ssl_inspect/engine.py before sslsplit is spawned.

    Returns (cert_path, key_path).
    """
    if not ca_exists():
        generate_ca()

    combined = CA_COMBINED_PATH.read_text(encoding="utf-8")

    import re as _re
    cert_match = _re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        combined, _re.DOTALL,
    )
    key_match = _re.search(
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----",
        combined, _re.DOTALL,
    )
    if not cert_match or not key_match:
        raise RuntimeError(
            "Combined PEM does not contain both a certificate and a private key"
        )

    SSLSplit_CERT_PATH.write_text(cert_match.group(0) + "\n", encoding="utf-8")
    SSLSplit_KEY_PATH.write_text(key_match.group(0) + "\n", encoding="utf-8")

    try:
        SSLSplit_KEY_PATH.chmod(0o600)
        SSLSplit_CERT_PATH.chmod(0o644)
    except OSError:
        pass

    logger.info(
        "Exported sslsplit CA files: %s, %s",
        SSLSplit_CERT_PATH, SSLSplit_KEY_PATH,
    )
    return SSLSplit_CERT_PATH, SSLSplit_KEY_PATH