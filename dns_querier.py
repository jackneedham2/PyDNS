import socket
import pprint
from helper_functions import *
from definition_maps import *

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
        outbytes += [0] # null octet for the root
        return outbytes

    def create_query_packet(self, d):
        packet = []
        packet += self.header
        packet += self.format_domain(d) # add question
        packet += [0, qtype_map_inv["A"]] # add QTYPE
        packet += [0, qclass_map_inv["IN"]] # add QCLASS
        return packet

    def query_domain(self,d, ip, port):
        packet = self.create_query_packet(d)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(bytes(packet), (ip,port))
        d = s.recvfrom(1024)
        return d


def parse_domain(d):
    p = d[0]
    i = 1
    outstr = ""
    while d[i] != 0:
        if p == 0:
            outstr += "."
            p = d[i]
        else:
            outstr += chr(d[i])
            p -= 1
        i += 1
    return (i, outstr)

my_querier = DNSQuerier()
r = my_querier.query_domain("google.com","216.239.32.10",53)[0]



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

parsed_question = parse_domain(r[12:-1])


type_offset = 12+parsed_question[0]+1
#print()
#print(r[12+39+2:12+39+2+2])
#nbo_to_int(r[type_offset:type_offset+2])

print()

resp = {
    "TransactionID": r[0:2],
    "Flags": flags,
    "# Questions": (r[4]<<8)+r[5],
    "# Answer RRs": (r[6]<<8)+r[7],
    "# Authority RRs": (r[8]<<8)+r[9],
    "# Additional RRs": (r[10]<<8)+r[11],
    "Question": parsed_question[1],
    "QType": qtype_map[int.from_bytes(r[type_offset:type_offset+2])],
    "QClass": qclass_map[int.from_bytes(r[type_offset+2:type_offset+4])]
}  

rr_offset = type_offset+4

if(r[rr_offset] & 192 == 192): # 192 = 0b11000000
    record = dict()
    domain_pointer = int.from_bytes([(r[rr_offset] & 63), r[rr_offset+1]])
    parsed_dom = parse_domain(r[domain_pointer:-1])
    record["Domain"] = parsed_dom[1]
    rr_offset += 2

    record["Type"] = (qtype_map[int.from_bytes(r[rr_offset:rr_offset+2])])
    record["Class"] = (qclass_map[int.from_bytes(r[rr_offset+2:rr_offset+4])])
    record["TTL"] = int.from_bytes(r[rr_offset+4:rr_offset+8])
    record["Data Length"] = int.from_bytes(r[rr_offset+8:rr_offset+10])
    if record["Type"] == "A":
        data_raw = r[rr_offset+10:rr_offset+10+record["Data Length"]]
        outstr = ""
        for b in data_raw[0:-1]:
            outstr += str(b)
            outstr += "."
        outstr += str(data_raw[-1])
        record["Data"] = outstr
    else:
        record["Data"] = r[rr_offset+10:rr_offset+10+record["Data Length"]]
    print(record)


#pprint.pp(resp)


