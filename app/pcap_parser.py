from scapy.all import rdpcap, IP, UDP, TCP, ICMP, Raw
from typing import List, Dict, Tuple
from collections import defaultdict, Counter
from datetime import datetime
import logging

from models import PacketInfo, TrafficStats

logger = logging.getLogger(__name__)


class PcapParser:
    def __init__(self, server_ip: str = None, game_port: int = 7787, query_port: int = 27165):
        self.server_ip = server_ip
        self.game_port = game_port
        self.query_port = query_port
        
    def parse_pcap(self, pcap_path: str) -> Tuple[List[PacketInfo], TrafficStats]:
        logger.info(f"Parsing PCAP file: {pcap_path}")
        
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            logger.error(f"Failed to read PCAP: {e}")
            raise
        
        packet_infos = []
        stats = self._initialize_stats()
        
        ip_counter = Counter()
        protocol_counter = Counter()
        size_buckets = defaultdict(int)
        
        first_timestamp = None
        last_timestamp = None
        
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
                
            ip_layer = pkt[IP]
            timestamp = float(pkt.time)
            
            if first_timestamp is None:
                first_timestamp = timestamp
            last_timestamp = timestamp
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = len(pkt)
            
            ip_counter[src_ip] += 1
            ip_counter[dst_ip] += 1
            
            protocol = "OTHER"
            src_port = None
            dst_port = None
            flags = None
            
            if pkt.haslayer(UDP):
                protocol = "UDP"
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                stats.udp_packets += 1
                
                if self.server_ip:
                    if (dst_ip == self.server_ip and dst_port == self.game_port) or \
                       (src_ip == self.server_ip and src_port == self.game_port):
                        stats.game_port_packets += 1
                    elif (dst_ip == self.server_ip and dst_port == self.query_port) or \
                         (src_ip == self.server_ip and src_port == self.query_port):
                        stats.query_port_packets += 1
                        
            elif pkt.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
                stats.tcp_packets += 1
                
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                stats.icmp_packets += 1
            else:
                stats.other_packets += 1
            
            protocol_counter[protocol] += 1
            
            size_bucket = self._get_size_bucket(length)
            size_buckets[size_bucket] += 1
            
            packet_info = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                flags=flags
            )
            packet_infos.append(packet_info)
            
            stats.total_packets += 1
            stats.total_bytes += length
        
        if first_timestamp and last_timestamp:
            duration = last_timestamp - first_timestamp
            if duration > 0:
                stats.packets_per_second = stats.total_packets / duration
                stats.bytes_per_second = stats.total_bytes / duration
        
        stats.unique_ips = len(ip_counter)
        stats.top_talkers = [
            {"ip": ip, "packets": count}
            for ip, count in ip_counter.most_common(10)
        ]
        stats.protocol_distribution = dict(protocol_counter)
        stats.packet_size_distribution = dict(size_buckets)
        
        logger.info(f"Parsed {stats.total_packets} packets, {stats.unique_ips} unique IPs")
        
        return packet_infos, stats
    
    def _initialize_stats(self) -> TrafficStats:
        return TrafficStats()
    
    def _get_size_bucket(self, size: int) -> str:
        if size < 64:
            return "0-64"
        elif size < 128:
            return "64-128"
        elif size < 256:
            return "128-256"
        elif size < 512:
            return "256-512"
        elif size < 1024:
            return "512-1024"
        elif size < 1500:
            return "1024-1500"
        else:
            return "1500+"
