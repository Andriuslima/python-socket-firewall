from struct import unpack
from math import inf
from binascii import hexlify
import signal
import heapq
import socket
import sys
import binascii

ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14
IP_PROTOCOL_NUMBER = 0x800
ARP_PROTOCOL_NUMBER = 0x806

TCP_PROTOCOL_NUMBER = 6
UDP_PROTOCOL_NUMBER = 17
ICMP_PROTOCOL_NUMBER = 1

ETHERNET_HEADER_PATTERN = "!6s6sH"
IP_HEADER_PATTERN = "!BBHHHBBH4s4s"
ARP_HEADER_PATTERN = "!2s2s1s1s2s6s4s6s4s"

TCP_HEADER_PATTERN = "!HHLLBBHHH"
UDP_HEADER_PATTERN = "!HHHH"
ICMP_HEADER_PATTERN = "!BBBBH"

INTERFACE = sys.argv[1]
HOST_MAC = ""

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    8: "Echo Request"
}

SUPPORTED_PROTOCOLS = [TCP_PROTOCOL_NUMBER, UDP_PROTOCOL_NUMBER, ICMP_PROTOCOL_NUMBER]


def bytes_to_mac(mac):
    return ":".join("{:02x}".format(x) for x in mac)


def search_and_log_tcp(packet, protocol, iph_length):
    if protocol == TCP_PROTOCOL_NUMBER:
        t = iph_length + ETH_HEADER_LEN
        tcp = unpack(TCP_HEADER_PATTERN, packet[t:t+20])

        source_port = tcp[0]
        dest_port = tcp[1]

        print("Protocol Name: TCP")
        print("Source Port: "+str(source_port))
        print("Destination Port: "+str(dest_port))


def search_and_log_udp(packet, protocol, iph_length):
    if protocol == UDP_PROTOCOL_NUMBER:
        u = iph_length + ETH_HEADER_LEN
        udph = unpack(UDP_HEADER_PATTERN, packet[u:u+8])

        source_port = udph[0]
        dest_port = udph[1]

        print("Protocol Name: UDP")
        print("Source Port: "+str(source_port))
        print("Destination Port: "+str(dest_port))


def search_and_log_icmp(packet, protocol, iph_length):
    if protocol == ICMP_PROTOCOL_NUMBER:
        u = iph_length + ETH_HEADER_LEN
        icmp = unpack(ICMP_HEADER_PATTERN, packet[u:u+6])

        icmp_type = icmp[0]
        code = icmp[1]
        checksum = icmp[2]
        icmp_id = icmp[3]
        icmp_sequence = icmp[4]

        print("*"*5 + "ICMP" + "*"*4)
        print("Protocol Name: ICMP")
        print("Type: ", ICMP_TYPES.get(icmp_type))
        if icmp_type == 0 or icmp_type == 8:
            h_size = ETH_HEADER_LEN + iph_length + 4
            data = packet[h_size:]
            print("ICMP ID: ", str(icmp_id))
            print("ICMP Sequence: ", str(icmp_sequence))
            print("ICMP code:", str(code))
            print("ICMP checksum:", str(checksum))
            print("Payload: ", str(data))


try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Socket could not be created: '+str(msg))
    sys.exit(1)

print('Socket created!')
s.bind((INTERFACE, 0))
HOST_MAC = s.getsockname()[4]
print("Bound to interface ", INTERFACE)

while 1:
    packet, _ = s.recvfrom(65536)

    eth_header = packet[0:ETH_HEADER_LEN]
    eth = unpack(ETHERNET_HEADER_PATTERN, eth_header)
    protocol = eth[2]
    mac_dst_bytes = eth[1]
    mac_src_bytes = eth[0]

    # print(f"Received packet designated to {mac_dst_bytes}, my mac is {HOST_MAC}")
    # print(f"With protocol {protocol}")

    # if mac_dst_bytes != HOST_MAC or protocol != IP_PROTOCOL_NUMBER:
    #     continue

    if protocol == IP_PROTOCOL_NUMBER:
        ip_header = unpack(IP_HEADER_PATTERN, packet[ETH_HEADER_LEN:20+ETH_HEADER_LEN])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ip_protocol = ip_header[6]
        s_addr = socket.inet_ntoa(ip_header[8])
        d_addr = socket.inet_ntoa(ip_header[9])

        if (ip_protocol in SUPPORTED_PROTOCOLS):
            ip_pack_type = eth[2]
            print("*"*5 + "IP PACKET" + "*"*5)
            print("MAC Dst: ", bytes_to_mac(mac_dst_bytes))
            print("MAC Dst Raw: ", hexlify(mac_dst_bytes))
            print("MAC Src: ", bytes_to_mac(mac_src_bytes))
            print("MAC Src Raw: ", hexlify(mac_src_bytes))
            print("Type: ", hex(ip_pack_type))
            print("IP Dst: "+d_addr)
            print("IP Src: "+s_addr)
            print("Protocol: "+str(ip_protocol))

            search_and_log_icmp(packet, ip_protocol, iph_length)
            search_and_log_tcp(packet, ip_protocol, iph_length)
            search_and_log_udp(packet, ip_protocol, iph_length)

            print("*"*10)

