import socket
import sys

from protocols.data import ethFrame
from protocols.network import ipv4
from protocols.transport import icmp
from protocols.transport import tcp
from protocols.transport import udp

IPV4HEADER = 8
tcpProto  = (tcp, "TCP", 6),
udpProto  = (udp, "UDP", 17),
icmpProto = (icmp, "ICMP", 1)
transportProtocols = [tcpProto, udpProto, icmpProto]

class Sniffer():
    def __init__(self, params):
        self.params = params

    def sniff(self.params):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while (True):
            rawData, addr = conn.recvfrom(9000)
            ethPacket = ethFrame.ethFrame(rawData)
            ethPacket.unpack()
            ethPacket.printInfo()

            if (ethPacket.protocol == IPV4HEADER):
                IPv4 = ipv4.IPv4(ethPacket.payload)
                IPv4.unpack()
                IPv4.printInfo()

                for proto in transportProtocols:
                    if (IPv4.protocol == proto[0][2]):
                        _class_ = getattr(proto[0][0], proto[0][1])
                        instance = _class_(IPv4.ipv4Data)
                        instance.unpack()
                        instance.printInfo()
                        break
