import socket
import sys

from protocols.data import ethFrame
from protocols.network import ipv4
from protocols.transport import icmp
from protocols.transport import tcp
from protocols.transport import udp

TCP = 6
ICMP = 1
UDP = 17
IPV4HEADER = 8

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (True):
        rawData, addr = conn.recvfrom(65536)
        ethPacket = ethFrame.ethFrame(rawData)
        ethPacket.unpack()
        ethPacket.printInfo()

        # Protocol 8 is IPv4
        if (ethPacket.protocol == IPV4HEADER):
            ipv4Header = ipv4.IPv4(ethPacket.payload)
            ipv4Header.unpack()
            ipv4Header.printInfo()

            if (ipv4Header.protocol == ICMP):
                icmpPacket = icmp.ICMP(ipv4Header.ipv4Data)
                icmpPacket.unpack()
                icmpPacket.printInfo()

            if (ipv4Header.protocol == TCP):
                tcpPacket = tcp.TCP(ipv4Header.ipv4Data)
                tcpPacket.unpack()
                tcpPacket.printInfo()

            if (ipv4Header.protocol == UDP):
                udpPacket = udp.UDP(ipv4Header.ipv4Data)
                udpPacket.unpack()
                udpPacket.printInfo()

main()
