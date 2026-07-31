from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime

def parse_packet(pkt):
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    parsed = {
        "timestamp": datetime.now(),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "proto": ip.proto,
        "size": len(pkt),
        "tcp": None,
        "udp": None,
        "icmp": None,
        "dns": None,
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        parsed["tcp"] = {
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": tcp.flags,
            "flags_str": str(tcp.flags),
        }
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        parsed["udp"] = {
            "src_port": udp.sport,
            "dst_port": udp.dport,
        }
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        parsed["icmp"] = {
            "type": icmp.type,
            "code": icmp.code,
        }

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        parsed["dns"] = {
            "query": pkt[DNSQR].qname.decode(errors="ignore"),
            "qtype": pkt[DNSQR].qtype,
        }

    return parsed