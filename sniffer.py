import socket
import struct
import textwrap

# AF_PACKET - All frames received by a given Ethernet
# SOCK_RAW - Capture the headers
# ntohs - "n" for network, "h" for host, "s" hort nand l "long"

# Ethernet Frame
#____________________________________________________________________________
#          |        |        |     |                                |        |
#          |        |        |     |                                |CRC     |
# Sync     |Receiver|Sender  |Type |Payload (IP/ARP Frame + padding)|(data   |
# 8 Bytes  |6 Bytes |6 Bytes |2    | 46 Bytes to 1500 Bytes         |check)  |
#          |        |        |Bytes|                                |4 Bytes |
# _________|________|________|_____|________________________________|________|

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (True):
        rawData, addr = conn.recvfrom(65536)
        destMac, srcMac, ethProt, data = unpackEthernetFrame(rawData)
        print("\nEthernet Frame:")
        print("Destination: {}, Source: {}, Protocol {}".format(destMac, srcMac, ethProt))

def unpackEthernetFrame(data):
    destMac, srcMac, proto = struct.unpack("! 6s 6s H", data[:14])
    return (getMacAddr(destMac), getMacAddr(srcMac), socket.htons(proto), data[14:])

# Formatting MAC addresss
def getMacAddr(bytesAddr):
    bytesStr = map('{:02X}'.format, bytesAddr) #formats each chunk to 2 decimal places and sets letters to Uppercase
    return (':'.join(bytesStr))

main()
