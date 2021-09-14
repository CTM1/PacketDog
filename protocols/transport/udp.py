import struct

class UDP:
    def __init__(self, data):
        self.rawData = data

    def unpack(self):
        self.srcPort, self.dstPort, self.size = struct.unpack("! H H 2x H", self.rawData[:8])
        self.udpData = self.rawData[8:]

    def printInfo(self):
        print("[.] UDP Protocol")
        print("\t[+] Source: {}, Destination: {}".format(self.srcPort, self.dstPort))
        print("\t[+] Size: {}".format(self.size))
        print("\t[+] Data: {}".format(self.udpData))
