import struct

class TCP:
    def __init__(self, data):
        self.rawData = data

    def unpack(self):
        self.srcPort, self.dstPort, self.sequence, self.ack, self.offsetReservedFlags = struct.unpack("! H H L L H", self.rawData[:14])
        self.offset = int(self.offsetReservedFlags >> 12) * 4 # Getting it in bytes
        self.flagNS  = (self.offsetReservedFlags & 256) >> 8
        self.flagCWR = (self.offsetReservedFlags & 128) >> 7
        self.flagECE = (self.offsetReservedFlags & 64) >> 6
        self.flagURG = (self.offsetReservedFlags & 32) >> 5
        self.flagACK = (self.offsetReservedFlags & 16) >> 4
        self.flagPSH = (self.offsetReservedFlags & 8) >> 3
        self.flagRST = (self.offsetReservedFlags & 4) >> 2
        self.flagSYN = (self.offsetReservedFlags & 2) >> 1
        self.flagFIN = (self.offsetReservedFlags & 1)
        self.tcpData = self.rawData[14:]

    def printInfo(self):
        print("[.] TCP Protocol")
        print("\t[+] Data Offset: {}".format(self.offset))
        print("\t[+] Source: {}, Destination: {}".format(self.srcPort, self.dstPort))
        print("\t[+] Sequence number: {}, Acknowledgement number: {}".format(self.sequence, self.ack))
        print("\t[+] NS: {}, CWR: {}, ECE: {}, URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(self.flagNS,
        self.flagCWR,
        self.flagECE,
        self.flagURG,
        self.flagACK,
        self.flagPSH,
        self.flagRST,
        self.flagSYN,
        self.flagFIN))
        print("\t[+] Data: {}".format(self.tcpData))
