#!/usr/bin/env python3
"""Check that a host serves a valid TLS certificate for its name.

Uses ssl.create_default_context(), so the certificate chain and the hostname
are always verified. There is deliberately no option to turn verification off.
TLS 1.2 is the minimum version. Prints metadata only: no page content is sent
or read, and exception text is never printed.

PASS means the channel reached a server holding a valid certificate for that
name. It does not mean the site or its content is trustworthy.
"""
import argparse
import re
import socket
import ssl
import sys
import time

# Hostnames and IPv4 addresses only, so nothing odd is echoed to the terminal.
HOST_PATTERN = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})')
PASS_MEANING = ('Note: PASS means the channel reached a server holding a valid certificate '
                'for this name, not that the site is trustworthy.')


def make_context(cafile: str | None = None) -> ssl.SSLContext:
    """Default context: chain and hostname checks on, TLS 1.2 minimum.

    cafile only adds an extra trust anchor (used by the offline tests with a
    throwaway lab CA). It never switches verification off.
    """
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # These are already the defaults; checking them makes the intent explicit.
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise RuntimeError('certificate verification must stay on')
    return context


def _name_field(name: tuple, field: str) -> str:
    """Pull one field (e.g. commonName) out of getpeercert()'s nested tuples."""
    for rdn in name:
        for key, value in rdn:
            if key == field:
                return value
    return '-'


def describe(cert: dict, version: str, cipher: str, now: float | None = None) -> list[str]:
    """Turn a verified peer certificate into a few safe lines of metadata."""
    now = time.time() if now is None else now
    sans = [v for k, v in cert.get('subjectAltName', ()) if k in ('DNS', 'IP Address')]
    not_after = cert.get('notAfter', '')
    days_left = int((ssl.cert_time_to_seconds(not_after) - now) // 86400) if not_after else None
    issuer = cert.get('issuer', ())
    return [
        f'TLS version: {version}',
        f'Cipher: {cipher}',
        f"Subject CN: {_name_field(cert.get('subject', ()), 'commonName')}",
        f'SANs: {len(sans)}; requested hostname matched: yes (verified during the handshake)',
        f"Issuer: O={_name_field(issuer, 'organizationName')}, CN={_name_field(issuer, 'commonName')}",
        f'Not after: {not_after} ({days_left} days remaining)',
    ]


def check(host: str, port: int = 443, timeout: float = 10.0, cafile: str | None = None) -> tuple[bool, list[str]]:
    """Connect, complete a verified TLS handshake, and return (passed, lines to print)."""
    context = make_context(cafile)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                lines = describe(tls.getpeercert(), tls.version(), tls.cipher()[0])
    except ssl.SSLCertVerificationError as err:
        # verify_message is OpenSSL's short reason, e.g. "self-signed certificate".
        return False, [f'FAIL: certificate verification failed: {err.verify_message}']
    except ssl.SSLError:
        return False, ['FAIL: TLS handshake failed (for example, no shared TLS 1.2+ version or cipher).']
    except OSError:
        return False, ['FAIL: could not connect (name lookup, refused connection or timeout).']
    return True, lines + ['PASS']


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('host', help='hostname to check, e.g. example.com')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--timeout', type=float, default=10.0, help='seconds (default 10)')
    args = parser.parse_args(argv)
    if not HOST_PATTERN.fullmatch(args.host) or not 0 < args.port < 65536 or args.timeout <= 0:
        print('Error: give a plain hostname, a port from 1 to 65535 and a positive timeout.', file=sys.stderr)
        return 2
    print(f'Host: {args.host}:{args.port}')
    passed, lines = check(args.host, args.port, args.timeout)
    for line in lines:
        print(line)
    print(PASS_MEANING)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
