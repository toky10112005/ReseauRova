# sniffer_to_file.py
import socket
import struct
import json
import time
import os

OUTPUT_FILE = "packets.json"
MAX_PACKETS = 50

# --- Utilitaire : conversion port → nom de service ---
def port_to_service(port, proto):
    services = {
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        67: 'DHCP',
        68: 'DHCP',
        123: 'NTP',
        1900: 'SSDP',
        5353: 'mDNS'
    }
    return services.get(port, str(port))

# --- Détecter si une IP est privée (LAN) ---
def is_private_ip(ip_str):
    try:
        a, b, c, d = map(int, ip_str.split('.'))
        return (
            a == 10 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168)
        )
    except:
        return False

def init_output_file():
    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump([], f)
        print(f"📁 Fichier {OUTPUT_FILE} réinitialisé.")
    except Exception as e:
        print(f"❌ Erreur initialisation fichier : {e}")
        exit(1)

def mac_to_str(mac): 
    return ':'.join(f'{b:02x}' for b in mac)

def ip_to_str(ip): 
    return '.'.join(str(b) for b in ip)

def parse_ethernet(data):
    if len(data) < 14:
        return None
    dst, src = data[0:6], data[6:12]
    eth_type = struct.unpack('!H', data[12:14])[0]
    return {
        'src_mac': mac_to_str(src),
        'dst_mac': mac_to_str(dst),
        'eth_type': eth_type,
        'payload': data[14:]
    }

def parse_ipv4(data):
    if len(data) < 20:
        return None
    version = (data[0] >> 4) & 0xF
    if version != 4:
        return None
    ihl = (data[0] & 0xF) * 4
    if len(data) < ihl:
        return None
    ttl, protocol = struct.unpack('!BB', data[8:10])
    src_ip = ip_to_str(data[12:16])
    dst_ip = ip_to_str(data[16:20])
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'ttl': ttl,
        'header_len': ihl,
        'payload': data[ihl:]
    }

def parse_arp(data):
    if len(data) < 28:
        return None
    opcode = struct.unpack('!H', data[6:8])[0]
    src_mac = mac_to_str(data[8:14])
    src_ip = ip_to_str(data[14:18])
    target_mac = mac_to_str(data[18:24])
    target_ip = ip_to_str(data[24:28])
    return {
        'opcode': opcode,
        'src_mac': src_mac,
        'src_ip': src_ip,
        'target_mac': target_mac,
        'target_ip': target_ip
    }

def parse_tcp(data):
    if len(data) < 20:
        return None
    src_port, dst_port = struct.unpack('!HH', data[0:4])
    flags = data[13]
    flag_names = []
    if flags & 0x02: flag_names.append("SYN")
    if flags & 0x10: flag_names.append("ACK")
    if flags & 0x01: flag_names.append("FIN")
    if flags & 0x04: flag_names.append("RST")
    if flags & 0x08: flag_names.append("PSH")
    if flags & 0x20: flag_names.append("URG")
    
    data_offset = (data[12] >> 4) * 4
    if len(data) < data_offset:
        return None

    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'flags': ','.join(flag_names) if flag_names else "NONE",
        'header_len': data_offset,
        'payload': data[data_offset:]
    }

def parse_udp(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack('!HHH', data[0:6])
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'payload': data[8:]
    }

def parse_icmp(data):
    if len(data) < 4:
        return None
    icmp_type, code = struct.unpack('!BB', data[0:2])
    type_names = {0: 'Echo Reply', 8: 'Echo Request'}
    return {
        'type': icmp_type,
        'code': code,
        'type_name': type_names.get(icmp_type, f"Type {icmp_type}")
    }

def write_packets(packets):
    temp_file = OUTPUT_FILE + ".tmp"
    try:
        with open(temp_file, 'w') as f:
            json.dump(packets, f, indent=2)
        os.replace(temp_file, OUTPUT_FILE)
    except Exception as e:
        print(f"Erreur écriture : {e}")

def capture_loop():
    packets = []
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("❌ Lancer avec sudo !")
        return

    print("📡 Capture en cours... (ARP + IPv4/TCP/UDP/ICMP)")
    while True:
        try:
            raw_data, _ = sock.recvfrom(65535)
            eth = parse_ethernet(raw_data)
            if not eth:
                continue

            packet = {
                'timestamp': time.time(),
                'eth': {
                    'src_mac': eth['src_mac'],
                    'dst_mac': eth['dst_mac'],
                    'eth_type': eth['eth_type']
                }
            }

            # 🔹 Cas ARP
            if eth['eth_type'] == 0x0806:  # ARP
                arp = parse_arp(eth['payload'])
                if arp:
                    packet['arp'] = arp

            # 🔹 Cas IPv4
            elif eth['eth_type'] == 0x0800:  # IPv4
                ip = parse_ipv4(eth['payload'])
                if not ip:
                    continue

                # ✅ Filtrer le trafic localhost
                if ip['src_ip'] == '127.0.0.1' and ip['dst_ip'] == '127.0.0.1':
                    continue

                packet['ip'] = {
                    'src_ip': ip['src_ip'],
                    'dst_ip': ip['dst_ip'],
                    'protocol': ip['protocol'],
                    'ttl': ip['ttl']
                }

                # Détection LAN vs Internet
                src_is_local = is_private_ip(ip['src_ip'])
                dst_is_local = is_private_ip(ip['dst_ip'])
                if src_is_local and dst_is_local:
                    packet['scope'] = 'LAN'
                else:
                    packet['scope'] = 'INTERNET'

                # ---- Analyse couche transport ----
                if ip['protocol'] == 6:  # TCP
                    tcp = parse_tcp(ip['payload'])
                    if tcp:
                        packet['tcp'] = {
                            'src_port': tcp['src_port'],
                            'dst_port': tcp['dst_port'],
                            'service': port_to_service(tcp['dst_port'], 'tcp'),
                            'flags': tcp['flags']
                        }
                elif ip['protocol'] == 17:  # UDP
                    udp = parse_udp(ip['payload'])
                    if udp:
                        packet['udp'] = {
                            'src_port': udp['src_port'],
                            'dst_port': udp['dst_port'],
                            'service': port_to_service(udp['dst_port'], 'udp')
                        }
                elif ip['protocol'] == 1:  # ICMP
                    icmp = parse_icmp(ip['payload'])
                    if icmp:
                        packet['icmp'] = icmp

            # Ajouter le paquet si utile
            if 'arp' in packet or 'ip' in packet:
                packets.insert(0, packet)
                if len(packets) > MAX_PACKETS:
                    packets = packets[:MAX_PACKETS]
                write_packets(packets)

        except Exception as e:
            print(f"Erreur capture : {e}")

if __name__ == "__main__":
    init_output_file()
    capture_loop()