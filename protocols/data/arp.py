import struct

class ARP:
    def __init__(self, data):
        self.rawData = data

    def unpack(self):
        hwType, proto, hLen, pLen, operation, senderHa, senderIp, targetHa, targetIp = struct.unpack('! H H B 1s H 6s 4s 6s 4s', self.rawData[:28])
        self.hwType     = hwType
        self.proto      = proto
        self.hLen       = hLen
        self.pLen       = pLen
        self.operation  = operation
        self.senderHa   = senderHa
        self.senderIp   = senderIp
        self.targetHa   = targetHa
        self.targetIp   = targetIp

    def printInfo(self):
        print("[.] ARP Packet") # 01 - Request, 02 - Reply (operation)
        print("\t[+] Hardware Type: {}, Header Length: {}, Op: {}, Protocol: {}".format(self.hwType, int(self.hLen), self.operation, self.proto))
        print("\t[+] Sender MAC: {}, Target MAC: {}".format(formatMac(self.senderHa), formatMac(self.targetHa)))
        print("\t[+] Sender IP: {}, Target IP: {}".format(formatIPv4(self.senderIp), formatIPv4(self.targetIp))) # Need to change it if it's IPv6

def formatMac(bytesAddr):
    bytesStr = map('{:02X}'.format, bytesAddr)
    return (':'.join(bytesStr))

def formatIPv4(bytesAddr):
    return ('.'.join(map(str, bytesAddr)))
