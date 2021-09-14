import struct

class IPv4:
    def __init__(self, data):
        self.rawData = data

    def unpack(self):
        versionHeaderLength = self.rawData[0]
        self.version        = versionHeaderLength >> 4
        self.headerLength   = (versionHeaderLength & 15) * 4 # 15 = 00001111 so we ignore the first word, multiply by 4 as seen above
        self.ipv4Data       = self.rawData[self.headerLength:]
        self.ttl, self.protocol, self.src, self.dst = struct.unpack("! 8x B B 2x 4s 4s", self.rawData[:20])

    def printInfo(self):
        print("[.] IPv4 Packet")
        print("\t[+] Version: {}, HeaderLength {}, TTL: {}".format(self.version, self.headerLength, self.ttl))
        print("\t[+] Protocol: {}, Source: {}, Target: {}".format(self.protocol, formatIPv4(self.src), formatIPv4(self.dst)))

def formatIPv4(bytesAddr):
    return ('.'.join(map(str, bytesAddr)))
