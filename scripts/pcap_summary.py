#!/usr/bin/env python3
"""Offline, educational metadata-only PCAP summary; never sends packets.

No stream reassembly or TLS decryption. HTTP headers/bodies are never printed.
Only known lab route names are shown; arbitrary paths, queries and fragments
are suppressed because they may contain credentials. DNS names and endpoints
are metadata and may still be private: review output before sharing it.
Byte counts are payload lengths only; payload content is never printed.
"""
import argparse
import re
import sys
from pathlib import Path

# Routes from my own lab that are safe to print. Anything else is counted, not shown.
SAFE_ROUTES = frozenset({b'/', b'/rest/user/login', b'/rest/user/whoami'})
# A complete HTTP/1.x request line at the start of a TCP segment.
REQUEST_LINE = re.compile(
    rb'(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ([^\s]+) HTTP/1\.[01]')
TLS_PORT = 443
DEFAULT_HANDSHAKE_TIMEOUT = 10.0  # seconds of capture time, not wall-clock time

# TCP flag bits
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


def strip_query_and_fragment(target: bytes) -> bytes:
    """Cut everything from the first ? or # so tokens in a query never reach the allowlist check."""
    return target.split(b'?', 1)[0].split(b'#', 1)[0]


def route_label(target: bytes) -> str | None:
    """Return the route to print, or None when it is not on the allowlist."""
    route = strip_query_and_fragment(target)
    return route.decode('ascii') if route in SAFE_ROUTES else None


def parse_request_line(payload: bytes) -> tuple[str, bytes] | None:
    """Return (method, request target) for an HTTP/1.x request line, else None."""
    match = REQUEST_LINE.fullmatch(payload.split(b'\r\n', 1)[0])
    if not match:
        return None
    return match[1].decode('ascii'), match[2]


class HandshakeTracker:
    """Follows SYN -> SYN-ACK -> ACK per connection, using capture timestamps only."""

    def __init__(self, timeout: float = DEFAULT_HANDSHAKE_TIMEOUT):
        self.timeout = timeout
        self.pending = {}  # (src, sport, dst, dport) of the SYN sender -> state
        self.expired = 0

    def expire(self, now: float) -> int:
        """Drop pending SYNs older than the timeout, measured in capture time."""
        stale = [k for k, s in self.pending.items() if now - s['ts'] > self.timeout]
        for key in stale:
            del self.pending[key]
        self.expired += len(stale)
        return len(stale)

    def on_segment(self, key, flags: int, seq: int, ack: int, ts: float) -> str | None:
        """Update state for one TCP segment; return 'syn', 'syn_ack', 'complete' or None."""
        reverse = (key[2], key[3], key[0], key[1])
        event = None
        if flags & SYN and not flags & ACK:
            self.pending[key] = {'seq': seq, 'syn_ack': None, 'ts': ts}
            event = 'syn'
        elif flags & SYN and flags & ACK:
            event = 'syn_ack'
            state = self.pending.get(reverse)
            if state and ack == (state['seq'] + 1) % 2**32:
                state['syn_ack'] = seq
        elif flags & ACK and not flags & (SYN | RST):
            state = self.pending.get(key)
            if (state and state['syn_ack'] is not None
                    and ack == (state['syn_ack'] + 1) % 2**32
                    and seq == (state['seq'] + 1) % 2**32):
                event = 'complete'
                self.pending.pop(key, None)
        if flags & (FIN | RST):
            # The connection is closing or refused, so forget it in both directions.
            self.pending.pop(key, None)
            self.pending.pop(reverse, None)
        return event


def tcp_payload_length(tcp) -> int:
    """Length of the TCP payload in bytes, ignoring Ethernet padding. Content is never read out."""
    from scapy.all import Padding
    length = len(tcp.payload)
    pad = tcp.getlayer(Padding)
    if pad is not None:
        length -= len(pad)
    return max(length, 0)


def summarise(path: Path, timeout: float) -> None:
    """Print a metadata-only summary of one capture. Raises on unreadable input."""
    from scapy.all import PcapReader, IP, IPv6, TCP, DNS, DNSQR
    tracker = HandshakeTracker(timeout)
    counts = {'packets': 0, 'dns_queries': 0, 'syn': 0, 'syn_ack': 0,
              'handshake_candidates': 0, 'http_requests': 0, 'http_paths_omitted': 0,
              'pending_expired': 0, 'pending_unfinished': 0, 'tcp_payload_bytes': 0,
              'tls_443_bytes_out': 0, 'tls_443_bytes_in': 0}
    # Never echo input filenames: a filename itself could contain sensitive text.
    print('Capture summary:')
    with PcapReader(str(path)) as reader:
        for number, pkt in enumerate(reader, 1):
            counts['packets'] += 1
            tracker.expire(float(pkt.time))
            net = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if DNS in pkt and int(pkt[DNS].qr) == 0 and DNSQR in pkt:
                q = pkt[DNSQR]
                name = bytes(q.qname).decode('ascii', 'replace').rstrip('.')
                # Escape unsafe characters to prevent terminal control sequences.
                name = re.sub(r'[^a-zA-Z0-9_.-]', '_', name)[:253]
                print(f'  #{number} DNS query {name} type={int(q.qtype)}')
                counts['dns_queries'] += 1
            if net is None or TCP not in pkt:
                continue
            t = pkt[TCP]
            key = (net.src, int(t.sport), net.dst, int(t.dport))
            event = tracker.on_segment(key, int(t.flags), int(t.seq), int(t.ack), float(pkt.time))
            if event == 'syn':
                counts['syn'] += 1
                print(f'  #{number} SYN {key[0]}:{key[1]} -> {key[2]}:{key[3]}')
            elif event == 'syn_ack':
                counts['syn_ack'] += 1
                print(f'  #{number} SYN-ACK {key[0]}:{key[1]} -> {key[2]}:{key[3]}')
            elif event == 'complete':
                counts['handshake_candidates'] += 1
                print(f'  #{number} ACK completing observed handshake candidate')
            # Byte counts are lengths only.
            size = tcp_payload_length(t)
            counts['tcp_payload_bytes'] += size
            if key[3] == TLS_PORT:
                counts['tls_443_bytes_out'] += size  # client -> server
            elif key[1] == TLS_PORT:
                counts['tls_443_bytes_in'] += size  # server -> client
            # Match only a complete HTTP/1.x request line at a segment start.
            # Do not load HTTP layers or print headers/body, even on port 3000.
            request = parse_request_line(bytes(t.payload))
            if request:
                method, target = request
                shown = route_label(target)
                if shown is None:
                    shown = '[path omitted]'
                    counts['http_paths_omitted'] += 1
                print(f'  #{number} plaintext HTTP {method} {shown}')
                counts['http_requests'] += 1
    counts['pending_expired'] = tracker.expired
    counts['pending_unfinished'] = len(tracker.pending)
    print('  Totals: ' + ', '.join(f'{k}={v}' for k, v in counts.items()))
    print('  TLS content is encrypted; no key loading/decryption. HTTP is segment-local, not stream-reassembled.')
    print('  SYN/ACK matches are candidates, not proof of application success; missing packets/retransmits affect results.')
    print(f'  Pending SYNs expire after {timeout:g}s of capture time; byte counts are TCP payload lengths only.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', nargs='+', type=Path)
    parser.add_argument('--handshake-timeout', type=float, default=DEFAULT_HANDSHAKE_TIMEOUT,
                        help='seconds of capture time before a pending SYN is dropped (default 10)')
    args = parser.parse_args(argv)
    if args.handshake_timeout <= 0:
        print('Error: --handshake-timeout must be greater than zero.', file=sys.stderr)
        return 2
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        print('Scapy is missing. Install with: python -m pip install -r requirements.txt', file=sys.stderr)
        return 2
    failed = False
    for path in args.captures:
        if not path.is_file():
            print('Error: an input capture is missing or is not a regular file.', file=sys.stderr)
            failed = True
            continue
        try:
            summarise(path, args.handshake_timeout)
        except Exception:
            # Exceptions may include packet contents, so emit only a fixed message.
            print('Error: unable to fully read capture; it may be invalid, truncated or inaccessible.', file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
