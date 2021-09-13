import socket
import struct
import textwrap



# Ethernet Frame
#_____________________________________________________________________________
#|          |        |        |     |                                |        |
#|          |        |        |     |                                |CRC     |
#| Sync     |Receiver|Sender  |Type |Payload (IP/ARP Frame + padding)|(data   |
#| 8 Bytes  |6 Bytes |6 Bytes |2    | 46 Bytes to 1500 Bytes         |check)  |
#|          |        |        |Bytes|                                |4 Bytes |
#|__________|________|________|_____|________________________________|________|

# IP Header
#_______________________________________________________  Byte Offset
#|Version  | IHL    | Service |      Total Length       |
#|(4 bits) |(4 bits)| (8 bits)|      (16 bits)          | 0
#|_________|________|_________|_________________________|
#|      Identification     |   Flags  | Fragment Offset |
#|       (16 bits)         | (3 bits) |    (13 bits)    | 4
#|_________________________|__________|_________________|
#|Time to Live | Protocol  |     Header Checksum        |
#| (8 bits)    | (8 bits)  |        (16 bits)           | 8
#|_____________|___________|____________________________|
#|                  Source IP (32 bits)                 | 12
#|______________________________________________________|
#|               Destination IP (32 bits)               | 16
#|______________________________________________________|
#|                    Data (32 bits)                    | 20
#|______________________________________________________|

# AF_PACKET - All frames received by a given Ethernet
# SOCK_RAW - Capture the headers
# ntohs / htons - "n"etwork, "h"ost, "s"hort and "l"ong

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (True):
        rawData, addr = conn.recvfrom(65536)
        dstMac, srcMac, ethProt, ethData = unpackEthernetFrame(rawData)
        print("\n[*] Ethernet Frame:")
        print("\t[+] Destination: {}, Source: {}, Protocol {}".format(dstMac, srcMac, ethProt))

        # Protocol 8 is IPv4
        if (ethProt == 8):
            version, headerLength, ttl, protocol, src, dst, IPv4Data = unpackIPv4(ethData)
            print("[.] IPv4 Packet")
            print("\t[+] Version: {}, HeaderLength {}, TTL: {}".format(version, headerLength, ttl))
            print("\t[+] Protocol: {}, Source: {}, Target: {}".format(protocol, src, dst))
            print(protocol)

            if (protocol == 1):
                ICMPType, code, checks, icmpData = unpackICMP(IPv4Data)

                print("[.] ICMP Protocol")
                print("\t[+] ICMP Type: {}, Code: {}, Data: {}".format(ICMPType, code, icmpData))
                print("\t[+] Checksum: {}".format(checks))
            if (protocol == 6):
                srcPort, dstPort, sequence, ackm, offsetReservedFlags,
                flagNS,
                flagACK,
                flagCWR,
                flagECE,
                flagFIN,
                flagPSH,
                flagRST,
                flagSYN,
                flagURG,
                tcpData = unpackTCP(IPv4Data)

                print("[.] TCP Protocol")
                print("\t[+] Data Offset: {}".format(offsetReservedFlags >> 9))
                print("\t[+] Source: {}, Destination: {}".format(srcPort, dstPort))
                print("\t[+] Sequence number: {}, Acknowledgement number: {}".format(sequence, ackm))
                print("\t[+] NS: {}, ACK: {}, CWR: {}, ECE: {}, FIN: {}, PSH: {}, RST: {}, SYN: {}, URG: {}".format(flagNS,
                flagACK,
                flagCWR,
                flagECE,
                flagFIN,
                flagPSH,
                flagRST,
                flagSYN,
                flagURG))
                print("\t[+] Data: {}".format(tcpData))

            if (protocol == 17):
                srcPort, dstPort, size, udpData = unpackUDP(IPv4Data)

                print("[.] UDP Protocol")
                print("\t[+] Source: {}, Destination: {}".format(srcPort, dstPort))
                print("\t[+] Size: {}".format(size))
                print("\t[+] Data: {}".format(udpData))

def unpackEthernetFrame(data):
    dstMac, srcMac, proto = struct.unpack("! 6s 6s H", data[:14])
    return (formatMac(dstMac), formatMac(srcMac), socket.htons(proto), data[14:])

# IHL (Header Length) only has 4 bits, but needs to describe lengths of up to 24
# bytes.
#
# It expresses the number in words (4 bytes), max IHL value is 15, max bytes in header is 24.
#
# Getting the array index comes down to multiplying the header length by 4.

def unpackIPv4(data):
    versionHeaderLength = data[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4 # 15 = 00001111 so we ignore the first word, multiply by 4 as seen above
    ttl, protocol, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return (version, headerLength, ttl, protocol, formatIPv4(src), formatIPv4(dst), data[headerLength:])

# Supported protocols
# 1 ICMP
# 6 TCP
# 17 UDP

# ICMP packet (in bytes)
#__________________________________
#|Type (1) | Code (1)| Checksum (2)| ICMP Header
#|_________|_________|_____________| 8 bytes
#|ID (2 bytes)| Sequence (2 bytes) |
#|____________|____________________| ==========
#| ICMP Data (x bytes)             | Data
#|_________________________________| (x bytes)

def unpackICMP(data):
    ICMPType, code, checks = struct.unpack('! B B H', data[:4])
    return (ICMPType, code, checks, data[4:])

# TCP packet (in bytes)
#_____________________________________________________
#|    Source port (16)       | Destination port (16)  |
#|___________________________|________________________|
#|               Sequence number (32)                 |
#|____________________________________________________|
#|           Acknowledgement number (32)              |
#|____________________________________________________|
#|Data|Res |N|C|E|U|A|P|R|S|F|                        |  Data offset specifies the
#|Offs|ervd|S|W|C|R|C|S|S|Y|I|      Window Size       |  size of the TCP header in
#|(4) | (3)| |R|E|G|K|H|T|N|N|         (16)           |  32 bit words.
#|____|____|_|_|_|_|_|_|_|_|_|________________________|
#|         Checksum          |     Urgent Pointer     |
#|           (16)            |          (16)          |
#|___________________________|________________________|
#|Options (32)Padded with 0s at the end if necessary  |
#|____________________________________________________|

def unpackTCP(data):
    srcPort, dstPort, sequence, ack, offsetReservedFlags = struct.unpack("! H H L L H", data[14:])
    offset   = offsetReservedFlags >> 12 * 4 # Getting it in bytes

    flagNS  = offsetReservedFlags & 256 >> 8
    flagCWR = offsetReservedFlags & 128 >> 7
    flagECE = offsetReservedFlags & 64 >> 6
    flagURG = offsetReservedFlags & 32 >> 5
    flagACK = offsetReservedFlags & 16 >> 4
    flagPSH = offsetReservedFlags & 8 >> 3
    flagRST = offsetReservedFlags & 4 >> 2
    flagSYN = offsetReservedFlags & 2 >> 1
    flagFIN = offsetReservedFlags & 1

    return (srcPort, dstPort, sequence, ackm, offsetReservedFlags,
    flagNS,
    flagACK,
    flagCWR,
    flagECE,
    flagFIN,
    flagPSH,
    flagRST,
    flagSYN,
    flagURG,
    data[offsetReservedFlags:])

# UDP Packet
#________________________________
#| Src Port (16) | Dst Port (16) |
#|_______________|_______________|
#| Length (16)   |UDP chksum (16)|
#|_______________|_______________|
#|              Data             |
#|              (32)             |
#|_______________________________|

def unpackUDP(data):
    srcPort, dstPort, size = struct.unpack("! H H 2x H", data[:8])
    return (srcPort, dstPort, size, data[8:])

# Formatting MAC addresss
def formatMac(bytesAddr):
    bytesStr = map('{:02X}'.format, bytesAddr) #formats each chunk to 2 decimal places and sets letters to Uppercase
    return (':'.join(bytesStr))

def formatIPv4(bytesAddr):
    return ('.'.join(map(str, bytesAddr)))

main()
