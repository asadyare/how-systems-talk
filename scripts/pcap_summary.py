#!/usr/bin/env python3
"""Offline, educational metadata-only PCAP summary; never sends packets.

No stream reassembly or TLS decryption. HTTP headers/bodies are never printed.
Only known lab route names are shown; arbitrary paths, queries and fragments
are suppressed because they may contain credentials. DNS names and endpoints
are metadata and may still be private: review output before sharing it.
"""
import argparse
import re
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, DNS, DNSQR
    except ImportError:
        print('Scapy is missing. Install with: python -m pip install -r requirements.txt', file=sys.stderr)
        return 2
    failed = False
    for path in args.captures:
        if not path.is_file():
            print('Error: an input capture is missing or is not a regular file.', file=sys.stderr)
            failed = True
            continue
        # Never echo input filenames: a filename itself could contain sensitive text.
        print('Capture summary:')
        pending = {}
        counts = {'packets': 0, 'dns_queries': 0, 'syn': 0, 'syn_ack': 0,
                  'handshake_candidates': 0, 'http_requests': 0}
        try:
            with PcapReader(str(path)) as reader:
                for number, pkt in enumerate(reader, 1):
                    counts['packets'] += 1
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
                    reverse = (key[2], key[3], key[0], key[1])
                    flags = int(t.flags)
                    if flags & 2 and not flags & 16:
                        pending[key] = {'seq': int(t.seq), 'syn_ack': None}
                        counts['syn'] += 1
                        print(f'  #{number} SYN {key[0]}:{key[1]} -> {key[2]}:{key[3]}')
                    elif flags & 2 and flags & 16:
                        counts['syn_ack'] += 1
                        print(f'  #{number} SYN-ACK {key[0]}:{key[1]} -> {key[2]}:{key[3]}')
                        state = pending.get(reverse)
                        if state and int(t.ack) == (state['seq'] + 1) % 2**32:
                            state['syn_ack'] = int(t.seq)
                    elif flags & 16 and not flags & (2 | 4):
                        state = pending.get(key)
                        if (state and state['syn_ack'] is not None
                                and int(t.ack) == (state['syn_ack'] + 1) % 2**32
                                and int(t.seq) == (state['seq'] + 1) % 2**32):
                            counts['handshake_candidates'] += 1
                            print(f'  #{number} ACK completing observed handshake candidate')
                            pending.pop(key, None)
                    if flags & (1 | 4):
                        pending.pop(key, None)
                        pending.pop(reverse, None)
                    # Match only a complete HTTP/1.x request line at a segment start.
                    # Do not load HTTP layers or print headers/body, even on port 3000.
                    payload = bytes(t.payload)
                    line = payload.split(b'\r\n', 1)[0]
                    match = re.fullmatch(rb'(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ([^\s]+) HTTP/1\.[01]', line)
                    if match:
                        method = match[1].decode('ascii')
                        route = match[2].split(b'?', 1)[0].split(b'#', 1)[0]
                        safe = {b'/', b'/rest/user/login', b'/rest/user/whoami'}
                        shown = route.decode('ascii') if route in safe else '[path omitted]'
                        print(f'  #{number} plaintext HTTP {method} {shown}')
                        counts['http_requests'] += 1
            print('  Totals: ' + ', '.join(f'{k}={v}' for k, v in counts.items()))
            print('  TLS content is encrypted; no key loading/decryption. HTTP is segment-local, not stream-reassembled.')
            print('  SYN/ACK matches are candidates, not proof of application success; missing packets/retransmits affect results.')
        except Exception:
            # Exceptions may include packet contents, so emit only a fixed message.
            print('Error: unable to fully read capture; it may be invalid, truncated or inaccessible.', file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
