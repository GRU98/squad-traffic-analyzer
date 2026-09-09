import pytest
from packets import GAME_PORT, QUERY_PORT, SERVER_IP, game_session, tcp, udp
from scapy.all import ARP, Ether

from pcap_parser import PcapParser


def test_parse_counts_packets_bytes_and_rates(pcap_builder):
    packets = [udp("1.1.1.1", size=100, t=0.0), udp("2.2.2.2", size=200, t=1.0), udp("1.1.1.1", size=300, t=2.0)]
    path = pcap_builder(packets)

    infos, stats = PcapParser().parse_pcap(path)

    assert len(infos) == 3
    assert stats.total_packets == 3
    assert stats.total_bytes == sum(len(p) for p in packets)
    assert stats.unique_ips == 3  # два источника + сервер
    assert stats.packets_per_second == pytest.approx(3 / 2.0)
    assert stats.bytes_per_second == pytest.approx(stats.total_bytes / 2.0)
    assert stats.udp_packets == 3
    assert stats.protocol_distribution == {"UDP": 3}
    assert infos[0].src_ip == "1.1.1.1" and infos[0].dst_port == GAME_PORT and infos[0].protocol == "UDP"


def test_parse_classifies_protocols_and_size_buckets(pcap_builder):
    path = pcap_builder([udp("1.1.1.1", size=10), tcp("1.1.1.1", flags="S"), udp("1.1.1.1", size=1400)])

    infos, stats = PcapParser().parse_pcap(path)

    assert stats.udp_packets == 2 and stats.tcp_packets == 1
    assert infos[1].protocol == "TCP" and "S" in infos[1].flags
    assert stats.packet_size_distribution["0-64"] == 2  # UDP с 10-байтовым payload и голый TCP SYN
    assert stats.packet_size_distribution["1024-1500"] == 1


def test_parse_counts_game_and_query_port_packets_only_with_server_ip(pcap_builder):
    packets = [
        udp("1.1.1.1", dport=GAME_PORT),
        udp(SERVER_IP, dst="1.1.1.1", sport=GAME_PORT, dport=40000),
        udp("1.1.1.1", dport=QUERY_PORT),
        udp("1.1.1.1", dport=9999),
    ]
    path = pcap_builder(packets)

    _, without_server = PcapParser().parse_pcap(path)
    _, with_server = PcapParser(server_ip=SERVER_IP).parse_pcap(path)

    assert without_server.game_port_packets == 0 and without_server.query_port_packets == 0
    assert with_server.game_port_packets == 2
    assert with_server.query_port_packets == 1


def test_parse_skips_non_ip_packets(pcap_builder):
    arp = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1")
    path = pcap_builder([arp, udp("1.1.1.1")])

    infos, stats = PcapParser().parse_pcap(path)

    assert len(infos) == 1 and stats.total_packets == 1


def test_parse_single_packet_has_zero_rates(pcap_builder):
    _, stats = PcapParser().parse_pcap(pcap_builder([udp("1.1.1.1")]))

    assert stats.packets_per_second == 0.0 and stats.bytes_per_second == 0.0


def test_parse_missing_file_raises(tmp_path):
    with pytest.raises((OSError, ValueError, Exception)):  # noqa: B017 — Scapy бросает Scapy_Exception/FileNotFoundError
        PcapParser().parse_pcap(str(tmp_path / "missing.pcap"))


def test_top_talkers_are_sorted_by_packet_count(pcap_builder):
    _, stats = PcapParser().parse_pcap(pcap_builder(game_session(clients=3, seconds=1, pps_per_client=5)))

    assert stats.top_talkers[0]["ip"] == SERVER_IP
    counts = [t["packets"] for t in stats.top_talkers]
    assert counts == sorted(counts, reverse=True)


def test_query_port_requests_and_responses_are_counted(pcap_builder):
    from packets import A2S_INFO_REQUEST

    packets = [
        udp("1.1.1.1", dport=QUERY_PORT, payload=A2S_INFO_REQUEST, t=0.0),
        udp("2.2.2.2", dport=QUERY_PORT, payload=A2S_INFO_REQUEST, t=0.1),
        udp("2.2.2.2", dport=QUERY_PORT, payload=b"\xff\xff\xff\xffU\xff\xff\xff\xff", t=0.2),  # A2S_PLAYER
        udp(SERVER_IP, dst="1.1.1.1", sport=QUERY_PORT, dport=50000, size=350, t=0.3),
        udp("3.3.3.3", dport=GAME_PORT, t=0.4),
    ]
    _, stats = PcapParser(server_ip=SERVER_IP).parse_pcap(pcap_builder(packets))

    assert stats.query_port_packets == 4
    assert stats.query_requests == 3
    assert stats.query_responses == 1
    assert stats.query_request_sources == 2
    assert stats.query_request_bytes == sum(len(p) for p in packets[:3])
    assert stats.query_response_bytes == len(packets[3])


def test_query_counters_stay_zero_without_server_ip(pcap_builder):
    from packets import A2S_INFO_REQUEST

    _, stats = PcapParser().parse_pcap(pcap_builder([udp("1.1.1.1", dport=QUERY_PORT, payload=A2S_INFO_REQUEST)]))

    assert stats.query_requests == 0 and stats.query_responses == 0 and stats.query_request_sources == 0
