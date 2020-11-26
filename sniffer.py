
from struct import unpack
from math import inf
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

sum_packages = 0
arp_packages_sum = 0
ip_packages_sum = 0
icmp_packages_sum = 0
tcp_packages_sum = 0
udp_packages_sum = 0

package_min_size = inf
package_max_size = 0

ip_send_freq = {}
ip_recv_freq = {}

icmp_type_freq = {"None": 0}
most_used_ports = {"None": 0}


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


def log_statistics(sig, frame):
    print("\n" + "-"*40)
    if sum_packages == 0:
        print("Zero information captured")
        print("-" * 40)
        sys.exit(1)

    print("Packages Sum: " + str(sum_packages))
    print("ARP Packages %: " + str((arp_packages_sum/sum_packages) * 100) + "%")
    print("IP Packages %: " + str((ip_packages_sum / sum_packages) * 100) + "%")
    print("ICMP Packages %: " + str((icmp_packages_sum / sum_packages) * 100) + "%")
    print("TCP Packages %: " + str((tcp_packages_sum / sum_packages) * 100) + "%")
    print("UDP Packages %: " + str((udp_packages_sum / sum_packages) * 100) + "%")

    print("Package Min Size: " + str(package_min_size))
    print("Package Max Size: " + str(package_max_size))

    heap_ip_send_freq = [(value, key) for key, value in ip_send_freq.items()]
    heap_ip_recv_freq = [(value, key) for key, value in ip_recv_freq.items()]
    most_ip_send = heapq.nsmallest(5, heap_ip_send_freq)
    most_ip_recv = heapq.nlargest(5, heap_ip_recv_freq)

    print("IP that most sent packages: " + str(most_ip_send))
    print("IP that most received packages: " + str(most_ip_recv))

    heap_icmp_type_freq = [(value, key) for key, value in icmp_type_freq.items()]
    most_icmp_type = heapq.nlargest(1, heap_icmp_type_freq)
    print("ICMP type most used: " + str(most_icmp_type))

    heap_most_used_ports = [(value, key) for key, value in most_used_ports.items()]
    most_used_ports_list = heapq.nlargest(3, heap_most_used_ports)
    print("Ports most used: " + str(most_used_ports_list))

    print("-"*40)
    sys.exit(0)


def search_and_log_arp(packet, protocol):
    arp_detailed = unpack(ARP_HEADER_PATTERN, packet[ETH_HEADER_LEN:42])

    if protocol == ARP_PROTOCOL_NUMBER:
        global arp_packages_sum
        arp_packages_sum += 1
        print("*"*5 + "ARP" + "*"*5)
        print("OpCode: "+str(binascii.hexlify(arp_detailed[4])))
        print("MAC Src: "+bytes_to_mac(arp_detailed[5]))
        print("IP Src: "+socket.inet_ntoa(arp_detailed[6]))
        print("MAC Dst: "+bytes_to_mac(arp_detailed[7]))
        print("IP Dst: "+socket.inet_ntoa(arp_detailed[8]))
        print("*"*10)


def search_and_log_tcp(packet, protocol, iph_length):
    if protocol == TCP_PROTOCOL_NUMBER:
        global tcp_packages_sum
        tcp_packages_sum += 1

        t = iph_length + ETH_HEADER_LEN
        tcp = unpack(TCP_HEADER_PATTERN, packet[t:t+20])

        source_port = tcp[0]
        current_port_freq = most_used_ports.get(source_port, 0)
        most_used_ports[source_port] = current_port_freq + 1

        dest_port = tcp[1]
        current_port_freq = most_used_ports.get(dest_port, 0)
        most_used_ports[dest_port] = current_port_freq + 1
    
        print("*"*5 + "TCP" + "*"*5)
        print("Source Port: "+str(source_port))
        print("Destination Port: "+str(dest_port))
        print("*"*10)


def search_and_log_udp(packet, protocol, iph_length):
    if protocol == UDP_PROTOCOL_NUMBER:
        global udp_packages_sum
        udp_packages_sum += 1
        u = iph_length + ETH_HEADER_LEN
        udph = unpack(UDP_HEADER_PATTERN, packet[u:u+8])

        source_port = udph[0]
        current_port_freq = most_used_ports.get(source_port, 0)
        most_used_ports[source_port] = current_port_freq + 1

        dest_port = udph[1]
        current_port_freq = most_used_ports.get(dest_port, 0)
        most_used_ports[dest_port] = current_port_freq + 1

        print("*"*5 + "UDP" + "*"*5)
        print("Source Port: "+str(source_port))
        print("Destination Port: "+str(dest_port))
        print("*"*10)


def search_and_log_icmp(packet, protocol, iph_length):
    if protocol == ICMP_PROTOCOL_NUMBER:
        global icmp_packages_sum
        icmp_packages_sum += 1
        u = iph_length + ETH_HEADER_LEN
        icmp = unpack(ICMP_HEADER_PATTERN, packet[u:u+6])

        icmp_type = icmp[0]
        code = icmp[1]
        checksum = icmp[2]
        icmp_id = icmp[3]
        icmp_sequence = icmp[4]

        curr_icmp_type_freq = icmp_type_freq.get(icmp_type, 0)
        icmp_type_freq[icmp_type] = curr_icmp_type_freq + 1

        print("*"*5 + "ICMP" + "*"*4)
        print("Type: "+str(icmp_type))
        if icmp_type == 0 or icmp_type == 8:
            h_size = ETH_HEADER_LEN + iph_length + 4 # icpm header len
            data = packet[h_size:]
            print("ID: "+str(icmp_id))
            print("ICMP Sequence: "+str(icmp_sequence))
            print("ICMP code:"+ str(code))
            print("ICMP checksum:"+str(checksum))
            print("Payload: "+str(data))
        print("*"*10)


signal.signal(signal.SIGINT, log_statistics)

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Socket could not be created: '+str(msg))
    sys.exit(1)

print('Socket created!')

s.bind(('ens33',0))

while 1:
    packet,_ = s.recvfrom(65536)

    sum_packages += 1

    eth_header = packet[0:ETH_HEADER_LEN]
    eth = unpack(ETHERNET_HEADER_PATTERN,eth_header)
    protocol = eth[2]

    print("*"*5 + "ETHERNET" + "*"*5)
    print("MAC Dst: "+bytes_to_mac(eth[0]))
    print("MAC Src: "+bytes_to_mac(eth[1]))
    print("Type: "+hex(eth[2]))
    print("*"*10)

    if protocol == IP_PROTOCOL_NUMBER:
        if len(packet) >= package_max_size:
            package_max_size = len(packet)

        if len(packet) <= package_min_size:
            package_min_size = len(packet)

        ip_packages_sum += 1
        iph = unpack(IP_HEADER_PATTERN, packet[ETH_HEADER_LEN:20+ETH_HEADER_LEN])

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print("*"*5 + "IP" + "*"*5)
        print("IP Dst: "+d_addr)
        print("IP Src: "+s_addr)
        print("Protocol: "+str(protocol))
        print("*"*10)

        current_ip_send_freq = ip_send_freq.get(s_addr, 0)
        ip_send_freq[s_addr] = current_ip_send_freq + 1

        current_ip_recv_freq = ip_send_freq.get(d_addr, 0)
        ip_recv_freq[d_addr] = current_ip_recv_freq + 1

        search_and_log_icmp(packet, protocol, iph_length)
        search_and_log_tcp(packet, protocol, iph_length)
        search_and_log_udp(packet, protocol, iph_length)
    else:
        search_and_log_arp(packet, protocol)
