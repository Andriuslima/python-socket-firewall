from struct import unpack, pack
from domain import PacketFlow
from os import system, name
from time import sleep
import socket
import sys
import select

ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14
IP_PROTOCOL_NUMBER = 0x800

TCP_PROTOCOL_NUMBER = 6
UDP_PROTOCOL_NUMBER = 17
ICMP_PROTOCOL_NUMBER = 1

ETHERNET_HEADER_PATTERN = "!6s6sH"
IP_HEADER_PATTERN = "!BBHHHBBH4s4s"

TCP_HEADER_PATTERN = "!HHLLBBHHH"
UDP_HEADER_PATTERN = "!HHHH"
ICMP_HEADER_PATTERN = "!BBBBH"

INTERFACE = sys.argv[1].strip()
HOST_MAC = ""
GATEWAY_MAC = sys.argv[2].strip()

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    8: "Echo Request"
}

flows = list()

SUPPORTED_PROTOCOLS = [TCP_PROTOCOL_NUMBER, UDP_PROTOCOL_NUMBER, ICMP_PROTOCOL_NUMBER]

mac_to_bytes = lambda m: bytes.fromhex(m.replace(':', ''))


def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def bytes_to_mac(mac):
    return ":".join("{:02x}".format(x) for x in mac)


def search_and_log_tcp(packet, protocol, iph_length):
    t = iph_length + ETH_HEADER_LEN
    tcp = unpack(TCP_HEADER_PATTERN, packet[t:t + 20])

    source_port = tcp[0]
    dest_port = tcp[1]

    return source_port, dest_port


def search_and_log_udp(packet, protocol, iph_length):
    u = iph_length + ETH_HEADER_LEN
    udph = unpack(UDP_HEADER_PATTERN, packet[u:u + 8])

    source_port = udph[0]
    dest_port = udph[1]

    return source_port, dest_port


def search_and_log_icmp(packet, protocol, iph_length):
    u = iph_length + ETH_HEADER_LEN
    icmp = unpack(ICMP_HEADER_PATTERN, packet[u:u + 6])

    icmp_type = icmp[0]
    code = icmp[1]
    checksum = icmp[2]
    icmp_id = icmp[3]
    icmp_sequence = icmp[4]

    if icmp_type == 0 or icmp_type == 8:
        h_size = ETH_HEADER_LEN + iph_length + 4
        data = packet[h_size:]


def print_flows():
    global flows
    clear()
    if len(flows) > 0:
        print("Current FLows: ", flush=True)
        for index, flow in enumerate(flows):
            print(f"{index}:{flow}")

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Socket could not be created: ' + str(msg))
    sys.exit(1)

print('Socket created!')
s.bind((INTERFACE, 0))
HOST_MAC = s.getsockname()[4]

inputs = [s, sys.stdin]
outputs = []

running = 1

while running:
    input_ready, output_ready, except_ready = select.select(inputs, outputs, [], 0.0001)

    for i in input_ready:
        if i == s:
            packet, _ = s.recvfrom(65536)

            eth_header = packet[0:ETH_HEADER_LEN]
            eth = unpack(ETHERNET_HEADER_PATTERN, eth_header)
            eth_protocol = eth[2]
            mac_dst_bytes = eth[0]

            if eth_protocol == IP_PROTOCOL_NUMBER and mac_dst_bytes == HOST_MAC:
                ip_header = unpack(IP_HEADER_PATTERN, packet[ETH_HEADER_LEN:20 + ETH_HEADER_LEN])
                version_ihl = ip_header[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4

                ip_protocol = ip_header[6]
                src = socket.inet_ntoa(ip_header[8])
                dst = socket.inet_ntoa(ip_header[9])
                port_src = None
                port_dst = None

                if ip_protocol in SUPPORTED_PROTOCOLS:
                    ip_pack_type = eth[2]
                    if ip_protocol == ICMP_PROTOCOL_NUMBER:
                        search_and_log_icmp(packet, ip_protocol, iph_length)
                    elif ip_protocol == TCP_PROTOCOL_NUMBER:
                        port_src, port_dst = search_and_log_tcp(packet, ip_protocol, iph_length)
                    elif ip_protocol == UDP_PROTOCOL_NUMBER:
                        port_src, port_dst = search_and_log_udp(packet, ip_protocol, iph_length)

                    flow = PacketFlow(str(src), str(dst), str(ip_protocol), str(port_src), str(port_dst))
                    flow_id = flow.id

                    if flow not in flows:
                        flows.append(flow)
                    else:
                        flow = next((f for f in flows if f.id == flow_id), None)

                    if (flow.enabled):
                        # Ethernet Header
                        dest_mac = mac_to_bytes(GATEWAY_MAC)
                        source_mac = HOST_MAC
                        eth_protocol = IP_PROTOCOL_NUMBER

                        eth_hdr = pack("!6s6sH", dest_mac, source_mac, eth_protocol)

                        red_packet = eth_hdr + packet[ETH_HEADER_LEN:]

                        flow.size += len(red_packet)

                        x = s.send(red_packet)
                print_flows()
        elif i == sys.stdin:
            line = sys.stdin.readline()
            if line == "Q\n":
                running = 0
                break
            elif line == "\n":
                print("Ok, moving on...")
            else:
                index = int(line.strip())
                flows[index].enabled = not flows[index].enabled
            sleep(0.5)

        sleep(0.1)