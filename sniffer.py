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
            print(protocol)

            if (protocol == 1):
                ICMPType, code, checks, icmpData = unpackICMP(IPv4Data)

                print("[.] ICMP Protocol")
                print("\t[+] ICMP Type: {}, Code: {}, Data: {}".format(ICMPType, code, icmpData))
                print("\t[+] Checksum: {}".format(checks))
            if (protocol == 6):
                srcPort, dstPort, sequence, ack, offsetReservedFlags, flagNS, flagACK, flagCWR, flagECE, flagFIN, flagPSH, flagRST, flagSYN, flagURG, tcpData = unpackTCP(IPv4Data)

                print("[.] TCP Protocol")
                print("\t[+] Data Offset: {}".format(offsetReservedFlags >> 9))
                print("\t[+] Source: {}, Destination: {}".format(srcPort, dstPort))
                print("\t[+] Sequence number: {}, Acknowledgement number: {}".format(sequence, ack))
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
    offset  = offsetReservedFlags >> 12 * 4 # Getting it in bytes
    flagNS  = offsetReservedFlags & 256 >> 8
    flagCWR = offsetReservedFlags & 128 >> 7
    flagECE = offsetReservedFlags & 64 >> 6
    flagURG = offsetReservedFlags & 32 >> 5
    flagACK = offsetReservedFlags & 16 >> 4
    flagPSH = offsetReservedFlags & 8 >> 3
    flagRST = offsetReservedFlags & 4 >> 2
    flagSYN = offsetReservedFlags & 2 >> 1
    flagFIN = offsetReservedFlags & 1

    return (srcPort, dstPort, sequence, ack, offsetReservedFlags,
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

def unpackUDP(data):
    srcPort, dstPort, size = struct.unpack("! H H 2x H", data[:8])
    return (srcPort, dstPort, size, data[8:])

# Formatting MAC addresss
def formatMac(bytesAddr):
    bytesStr = map('{:02X}'.format, bytesAddr) #formats each chunk to 2 decimal places and sets letters to Uppercase
    return (':'.join(bytesStr))

def formatIPv4(bytesAddr):
    return ('.'.join(map(str, bytesAddr)))

def addPadding(data):
    print(bytes(0))
    for i in range(0, 400):
        data += bytes(0)
        i += 1
    print(data)
    return (data)

main()
