import struct

class ICMP:
    def __init__(self, data):
        self.rawData = data

    def unpack(self):
        ICMPType, code, checks = struct.unpack('! B B H', self.rawData[:4])
        self.type     = ICMPType
        self.code     = code
        self.checksum = checks

    def printInfo(self):
        print("[.] ICMP Protocol")
        print("\t[+] ICMP Type: {}, Code: {}, Data: {}".format(self.type, self.code, self.checksum))
        print("\t[+] Checksum: {}".format(self.checksum))
