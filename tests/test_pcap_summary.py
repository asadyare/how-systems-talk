"""Tests for pcap_summary.py using synthetic packets written to temporary pcaps."""
import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

import pcap_summary as ps

CLIENT, SERVER = '10.0.0.1', '10.0.0.2'


def seg(flags, seq=0, ack=0, sport=40000, dport=80, src=CLIENT, dst=SERVER, load=None, t=0.0):
    """Build one TCP segment with a chosen capture timestamp."""
    pkt = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if load is not None:
        pkt = pkt / Raw(load=load)
    pkt.time = t
    return pkt


def handshake(dport=80, t=0.0):
    return [seg('S', seq=100, dport=dport, t=t),
            seg('SA', seq=500, ack=101, sport=dport, dport=40000, src=SERVER, dst=CLIENT, t=t + 0.01),
            seg('A', seq=101, ack=501, dport=dport, t=t + 0.02)]


def run(tmp_path, capsys, packets, *extra):
    path = tmp_path / 'test.pcap'
    wrpcap(str(path), packets)
    code = ps.main([str(path), *extra])
    out = capsys.readouterr()
    return code, out.out, out.err


def totals(stdout):
    line = next(l for l in stdout.splitlines() if 'Totals:' in l)
    return dict(item.split('=') for item in line.split('Totals: ')[1].split(', '))


# ---------- route labelling (pure functions) ----------
@pytest.mark.parametrize('target,expected', [
    (b'/rest/user/login?token=abc', '/rest/user/login'),
    (b'/#frag', '/'),
    (b'/rest/user/whoami#x?y', '/rest/user/whoami'),
    (b'/admin', None),
    (b'/rest/user/login/extra', None),
])
def test_route_label_strips_query_and_fragment(target, expected):
    assert ps.route_label(target) == expected


def test_allowlisted_route_shown_after_query_stripped(tmp_path, capsys):
    pkts = handshake() + [seg('PA', seq=101, ack=501, load=b'GET /rest/user/login?next=1#top HTTP/1.1\r\nHost: x\r\n\r\n', t=0.1)]
    code, out, _ = run(tmp_path, capsys, pkts)
    assert code == 0
    assert 'plaintext HTTP GET /rest/user/login' in out and 'next=1' not in out and '#top' not in out
    assert totals(out)['http_paths_omitted'] == '0'


def test_unknown_path_omitted_and_counted(tmp_path, capsys):
    pkts = [seg('PA', load=b'GET /secret/area HTTP/1.1\r\n\r\n'), seg('PA', load=b'POST /other HTTP/1.0\r\n\r\n')]
    _, out, _ = run(tmp_path, capsys, pkts)
    assert out.count('[path omitted]') == 2 and '/secret/area' not in out
    assert totals(out)['http_paths_omitted'] == '2' and totals(out)['http_requests'] == '2'


def test_query_token_never_printed(tmp_path, capsys):
    secret = 'SECRET-TOKEN-VALUE-123'
    pkts = [seg('PA', load=f'GET /?token={secret} HTTP/1.1\r\nAuthorization: Bearer {secret}\r\n\r\n'.encode()),
            seg('PA', load=f'GET /x?token={secret} HTTP/1.1\r\n\r\n'.encode())]
    _, out, err = run(tmp_path, capsys, pkts)
    assert secret not in out and secret not in err and 'token=' not in out


# ---------- handshake state ----------
def test_handshake_completes_and_nothing_left_pending(tmp_path, capsys):
    _, out, _ = run(tmp_path, capsys, handshake())
    t = totals(out)
    assert t['handshake_candidates'] == '1' and t['pending_unfinished'] == '0'


@pytest.mark.parametrize('flag', ['R', 'F', 'RA', 'FA'])
def test_fin_or_rst_clears_pending(flag):
    tracker = ps.HandshakeTracker()
    key = (CLIENT, 40000, SERVER, 80)
    tracker.on_segment(key, 0x02, 100, 0, 0.0)
    assert key in tracker.pending
    flags = int(TCP(flags=flag).flags)
    # The close can come from either side.
    tracker.on_segment((SERVER, 80, CLIENT, 40000), flags, 500, 101, 0.1)
    assert tracker.pending == {}


def test_rst_reply_leaves_nothing_unfinished(tmp_path, capsys):
    pkts = [seg('S', seq=100, t=0.0), seg('RA', ack=101, sport=80, dport=40000, src=SERVER, dst=CLIENT, t=0.01)]
    _, out, _ = run(tmp_path, capsys, pkts)
    assert totals(out)['pending_unfinished'] == '0' and totals(out)['handshake_candidates'] == '0'


def test_timeout_uses_capture_time_not_wall_clock(tmp_path, capsys):
    # The SYN is never answered; a packet 30 s later in capture time expires it.
    pkts = [seg('S', seq=100, t=1000.0), seg('S', seq=900, sport=40001, t=1030.0)]
    _, out, _ = run(tmp_path, capsys, pkts, '--handshake-timeout', '10')
    t = totals(out)
    assert t['pending_expired'] == '1' and t['pending_unfinished'] == '1'


def test_late_ack_after_timeout_is_not_a_handshake(tmp_path, capsys):
    pkts = handshake(t=0.0)
    pkts[2].time = 20.0  # final ACK arrives 20 s after the SYN
    _, out, _ = run(tmp_path, capsys, pkts, '--handshake-timeout', '5')
    assert totals(out)['handshake_candidates'] == '0' and totals(out)['pending_expired'] == '1'


def test_tracker_expire_is_pure_capture_time():
    tracker = ps.HandshakeTracker(timeout=10)
    tracker.on_segment(('a', 1, 'b', 2), 0x02, 1, 0, 50.0)
    assert tracker.expire(59.0) == 0 and tracker.expire(61.0) == 1 and tracker.expired == 1


# ---------- byte counts ----------
def test_byte_counts_per_direction(tmp_path, capsys):
    pkts = handshake(dport=443) + [
        seg('PA', seq=101, ack=501, dport=443, load=b'x' * 300, t=0.1),
        seg('PA', seq=501, ack=401, sport=443, dport=40000, src=SERVER, dst=CLIENT, load=b'y' * 1200, t=0.2),
        seg('PA', dport=80, load=b'z' * 7, t=0.3),
    ]
    _, out, _ = run(tmp_path, capsys, pkts)
    t = totals(out)
    assert t['tls_443_bytes_out'] == '300' and t['tls_443_bytes_in'] == '1200'
    assert t['tcp_payload_bytes'] == str(300 + 1200 + 7)
    assert 'yyyy' not in out and 'xxxx' not in out


def test_ethernet_padding_not_counted(tmp_path, capsys):
    # Short frames are padded on the wire; the padding sits after the IP packet and is not TCP payload.
    padded = Ether(bytes(seg('A', load=b'abcd')) + b'\x00' * 6)
    _, out, _ = run(tmp_path, capsys, [padded])
    assert totals(out)['tcp_payload_bytes'] == '4'


# ---------- errors ----------
def test_missing_file_fixed_error_no_filename(tmp_path, capsys):
    name = 'private-case-name.pcap'
    code = ps.main([str(tmp_path / name)])
    out = capsys.readouterr()
    assert code == 1
    assert out.err.strip() == 'Error: an input capture is missing or is not a regular file.'
    assert 'private-case-name' not in out.out + out.err


def test_corrupt_file_fixed_error_no_bytes(tmp_path, capsys):
    path = tmp_path / 'bad.pcap'
    path.write_bytes(b'NOT-A-PCAP leaked-bytes-here')
    code = ps.main([str(path)])
    out = capsys.readouterr()
    assert code == 1 and 'leaked-bytes-here' not in out.out + out.err and 'bad.pcap' not in out.out + out.err
