import socket
from helper_functions import *

class DNSQuerier:
    header = [
        255,255, # Transaction ID
        1,0, # Flags
        0,1, # Num questions
        0,0, # Num Answer RRs
        0,0, # Num Authority RRs
        0,0, # Num Additional RRs
    ]
    def __init__(self):
        pass

    def format_domain(self, s):
        spl = s.split(".")
        outbytes = []
        for section in spl:
            outbytes += [len(section)]
            for c in section:
                outbytes += [ord(c)]
        return outbytes

    def create_query_packet(self, d):
        packet = []
        packet += self.header
        packet += self.format_domain(d)
        packet += [0,0]
        packet += [1, 0] # Type: PTR Record
        packet += [1, 0] # QCLASS = IN
        packet += [0x80, 0x1]
        return packet

    def query_domain(self,d, ip, port):
        packet = self.create_query_packet(d)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(bytes(packet), (ip,port))
        d = s.recvfrom(1024)
        return d

my_querier = DNSQuerier()
r = my_querier.query_domain("google.com","216.239.32.10",53)[0]

# These definitions all taken from rfc1035

opcode_map = ["QUERY", "IQUERY", "STATUS"]
rcode_map = ["No Error", "Format Error", "Server Failure", "Name Error", "Not Implemented", "Refused"]

flags = {
    "QR": r[2] >> 7,
    "OPCODE": opcode_map[(r[2] & 0b01111000) >> 3],
    "AA": bool((r[2] & 0b00000100) >> 2),
    "TC": bool((r[2] & 0b00000010) >> 1),
    "RD": bool(r[2] & 0b00000001),
    "RA": bool((r[3] & 0b10000000) >> 7),
    "Z": (r[3] & 0b01110000) >> 4,
    "RCODE": rcode_map[r[3] & 0b00001111]

}

print(my_querier.format_domain("google.com"))

parsed_question = {
    r[12:28]
}

resp = {
    "TransactionID": r[0:2],
    "Flags": flags,
    "# Questions": (r[4]<<8)+r[5],
    "# Answer RRs": (r[6]<<8)+r[7],
    "# Authority RRs": (r[8]<<8)+r[9],
    "# Additional RRs": (r[10]<<8)+r[11],
    "Question": parsed_question
}  


print(resp)


