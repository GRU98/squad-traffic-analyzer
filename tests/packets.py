"""Хелперы для генерации Scapy-пакетов с контролируемыми временными метками."""

from scapy.all import IP, TCP, UDP, Ether, Raw

SERVER_IP = "10.0.0.1"
GAME_PORT = 7787
QUERY_PORT = 27165

A2S_INFO_REQUEST = b"\xff\xff\xff\xffTSource Engine Query\x00"


def _eth():
    # Явные MAC-адреса: без них Scapy лезет в ARP/BPF и ругается при сборке пакета.
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def udp(src, dst=SERVER_IP, sport=50000, dport=GAME_PORT, size=120, t=0.0, payload=None):
    """UDP-пакет с payload заданного размера (или явным payload) и меткой времени t (секунды)."""
    load = payload if payload is not None else b"x" * size
    pkt = _eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=load)
    pkt.time = t
    return pkt


def tcp(src, dst=SERVER_IP, sport=50000, dport=21114, flags="S", t=0.0):
    pkt = _eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = t
    return pkt


def game_session(clients=10, seconds=10, pps_per_client=30):
    """Нормальная игровая сессия: каждый клиент шлёт и получает пакеты на game_port."""
    packets = []
    for c in range(clients):
        client_ip = f"192.168.1.{c + 10}"
        for i in range(seconds * pps_per_client):
            t = i / pps_per_client
            packets.append(udp(client_ip, sport=40000 + c, size=100, t=t))
            packets.append(udp(SERVER_IP, dst=client_ip, sport=GAME_PORT, dport=40000 + c, size=300, t=t + 0.001))
    packets.sort(key=lambda p: p.time)
    return packets
