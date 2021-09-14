import socket
import struct
import textwrap


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

            if (protocol == 1):
                ICMPType, code, checks, icmpData = unpackICMP(IPv4Data)

                print("[.] ICMP Protocol")
                print("\t[+] ICMP Type: {}, Code: {}, Data: {}".format(ICMPType, code, icmpData))
                print("\t[+] Checksum: {}".format(checks))
            if (protocol == 6):
                srcPort, dstPort, sequence, ack, offset, flagNS, flagCWR, flagECE, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, tcpData = unpackTCP(IPv4Data)

                print("[.] TCP Protocol")
                print("\t[+] Data Offset: {}".format(offset))
                print("\t[+] Source: {}, Destination: {}".format(srcPort, dstPort))
                print("\t[+] Sequence number: {}, Acknowledgement number: {}".format(sequence, ack))
                print("\t[+] NS: {}, CWR: {}, ECE: {}, URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flagNS,
                flagCWR,
                flagECE,
                flagURG,
                flagACK,
                flagPSH,
                flagRST,
                flagSYN,
                flagFIN))
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

def unpackIPv4(data):
    versionHeaderLength = data[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4 # 15 = 00001111 so we ignore the first word, multiply by 4 as seen above
    ttl, protocol, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return (version, headerLength, ttl, protocol, formatIPv4(src), formatIPv4(dst), data[headerLength:])


def unpackICMP(data):
    ICMPType, code, checks = struct.unpack('! B B H', data[:4])
    return (ICMPType, code, checks, data[4:])

def unpackTCP(data):
    srcPort, dstPort, sequence, ack, offsetReservedFlags = struct.unpack("! H H L L H", data[:14])
    offset = int(offsetReservedFlags >> 12) * 4 # Getting it in bytes
    print(offsetReservedFlags)
    flagNS  = (offsetReservedFlags & 256) >> 8
    flagCWR = (offsetReservedFlags & 128) >> 7
    flagECE = (offsetReservedFlags & 64) >> 6
    flagURG = (offsetReservedFlags & 32) >> 5
    flagACK = (offsetReservedFlags & 16) >> 4
    flagPSH = (offsetReservedFlags & 8) >> 3
    flagRST = (offsetReservedFlags & 4) >> 2
    flagSYN = (offsetReservedFlags & 2) >> 1
    flagFIN = (offsetReservedFlags & 1)

    return (srcPort, dstPort, sequence, ack, offset,
    flagNS,
    flagCWR,
    flagECE,
    flagURG,
    flagACK,
    flagPSH,
    flagRST,
    flagSYN,
    flagFIN,
    data[14:])

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
