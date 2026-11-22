"""Offline tests for tls_check.py against a local TLS server in a thread.

Throwaway keys and certificates are generated into pytest's tmp_path at run
time and deleted afterwards; none are committed.
"""
import datetime
import os
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import tls_check

HOST = 'localhost'


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Lab'),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, sans, issuer_cert=None, issuer_key=None, ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(subject_cn))
               .issuer_name(issuer_cert.subject if issuer_cert else _name(subject_cn))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                                      content_commitment=False, key_encipherment=False,
                                                      data_encipherment=False, key_agreement=False,
                                                      encipher_only=False, decipher_only=False), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def _write(tmp_path, name, cert, key=None):
    cert_path = tmp_path / f'{name}.crt'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = None
    if key is not None:
        key_path = tmp_path / f'{name}.key'
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
    return cert_path, key_path


@pytest.fixture
def tls_server():
    """Start a one-connection TLS server on 127.0.0.1 and yield its port."""
    servers = []

    def start(cert_path, key_path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        listener = socket.create_server(('127.0.0.1', 0))
        listener.settimeout(5)
        servers.append(listener)

        def serve():
            try:
                conn, _ = listener.accept()
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)  # wait for the client to close
            except (OSError, ssl.SSLError):
                pass  # the client is expected to reject some certificates

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    yield start
    for listener in servers:
        listener.close()


@pytest.fixture
def lab_ca(tmp_path):
    ca_cert, ca_key = _cert('Test Lab Root', None, ca=True)
    ca_path, _ = _write(tmp_path, 'ca', ca_cert)
    return ca_cert, ca_key, str(ca_path)


def test_self_signed_certificate_fails(tmp_path, tls_server):
    cert, key = _cert(HOST, [HOST])
    port = tls_server(*_write(tmp_path, 'self', cert, key))
    passed, lines = tls_check.check(HOST, port, timeout=5)
    assert not passed
    assert lines[0].startswith('FAIL: certificate verification failed:') and 'self-signed' in lines[0]


def test_hostname_mismatch_fails_even_with_trusted_ca(tmp_path, tls_server, lab_ca):
    ca_cert, ca_key, ca_path = lab_ca
    cert, key = _cert('wrong.example', ['wrong.example'], ca_cert, ca_key)
    port = tls_server(*_write(tmp_path, 'wrong', cert, key))
    passed, lines = tls_check.check(HOST, port, timeout=5, cafile=ca_path)
    assert not passed and 'Hostname mismatch' in lines[0]


def test_valid_chain_and_name_passes(tmp_path, tls_server, lab_ca):
    ca_cert, ca_key, ca_path = lab_ca
    cert, key = _cert(HOST, [HOST, 'alt.localhost'], ca_cert, ca_key)
    port = tls_server(*_write(tmp_path, 'good', cert, key))
    passed, lines = tls_check.check(HOST, port, timeout=5, cafile=ca_path)
    assert passed and lines[-1] == 'PASS'
    text = '\n'.join(lines)
    assert 'Subject CN: localhost' in text and 'SANs: 2' in text
    assert 'Issuer: O=Test Lab, CN=Test Lab Root' in text and 'days remaining' in text
    assert lines[0] in ('TLS version: TLSv1.2', 'TLS version: TLSv1.3')


def test_context_keeps_verification_on_and_tls12_minimum():
    ctx = tls_check.make_context()
    assert ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_no_insecure_option():
    with pytest.raises(SystemExit):
        tls_check.main(['example.com', '--insecure'])


def test_connection_refused_gives_fixed_message():
    with socket.create_server(('127.0.0.1', 0)) as s:
        port = s.getsockname()[1]
    passed, lines = tls_check.check('127.0.0.1', port, timeout=2)
    assert not passed and lines == ['FAIL: could not connect (name lookup, refused connection or timeout).']


def test_rejects_odd_hostnames(capsys):
    assert tls_check.main(['bad\x1b[31mhost']) == 2
    assert '\x1b' not in capsys.readouterr().err


@pytest.mark.network
def test_example_com_passes_live():
    passed, lines = tls_check.check('example.com')
    assert passed and lines[-1] == 'PASS'
