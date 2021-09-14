import struct
import socket

class ethFrame:
    def __init__(self, data):
        self.rawData = data

    def unpack(self):
        self.dstMac, self.srcMac, proto = struct.unpack("! 6s 6s H", self.rawData[:14])
        self.protocol = socket.htons(proto)
        self.payload = self.rawData[14:]

    def printInfo(self):
        print("\n[*] Ethernet Frame:")
        print("\t[+] Destination: {}, Source: {}, Protocol {}".format(formatMac(self.dstMac), formatMac(self.srcMac), self.protocol))

def formatMac(bytesAddr):
    bytesStr = map('{:02X}'.format, bytesAddr) #formats each chunk to 2 decimal places and sets letters to Uppercase
    return (':'.join(bytesStr))
