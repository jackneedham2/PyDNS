import socket
import pprint
from helper_functions import *
from definition_maps import *

header = [
    255,255, # Transaction ID
    1,0, # Flags
    0,1, # Num questions
    0,0, # Num Answer RRs
    0,0, # Num Authority RRs
    0,0, # Num Additional RRs
]


def format_domain(s):
    spl = s.split(".")
    outbytes = []
    for section in spl:
        outbytes += [len(section)]
        for c in section:
            outbytes += [ord(c)]
    outbytes += [0] # null octet for the root
    return outbytes

def create_query_packet(d,qtype):
    packet = []
    packet += header
    packet += format_domain(d) # add question
    packet += [0, qtype_map_inv[qtype]] # add QTYPE
    packet += [0, qclass_map_inv["IN"]] # add QCLASS
    return packet

def construct_header(h):
    ch = [] # ch for constructed header

    ch += [((h["ID"] & 65535) >> 8), (h["ID"] & 255)] # 16 bit ID
    if h["QR"] == "Query":
        ch += [0]
    elif h["QR"] == "Response":
        ch += [1]
    else:
        raise Exception("QR value of "+h["QR"]+" is invalid. Must be 'Query' or 'Response'.")


    if h["OPCODE"] == "QUERY":
        ch += [0]
    elif h["OPCODE"] == "IQUERY":
        ch += [1]
    elif h["OPCODE"] == "STATUS":
        ch += [2]
    else:
        raise Exception("OPCODE value of "+h["OPCODE"]+" is invalid. Must be QUERY, IQUERY or STATUS.")

    return ch

def query_domain(d, ip, qtype, port):
    packet = create_query_packet(d,qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(bytes(packet), (ip,port))
    r = s.recvfrom(1024)
    return r

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


def parse_response(r):
    parsed_question = parse_domain(r[12:-1])
    rr_offset = 12+parsed_question[0]+1

    resp = {
        "TransactionID": r[0:2],
        "Flags": {
            "QR": r[2] >> 7,
            "OPCODE": opcode_map[(r[2] & 0b01111000) >> 3],
            "AA": bool((r[2] & 0b00000100) >> 2),
            "TC": bool((r[2] & 0b00000010) >> 1),
            "RD": bool(r[2] & 0b00000001),
            "RA": bool((r[3] & 0b10000000) >> 7),
            "Z": (r[3] & 0b01110000) >> 4,
            "RCODE": rcode_map[r[3] & 0b00001111]
        },
        "# Questions": (r[4]<<8)+r[5],
        "# Answer RRs": (r[6]<<8)+r[7],
        "# Authority RRs": (r[8]<<8)+r[9],
        "# Additional RRs": (r[10]<<8)+r[11],
        "Question": parsed_question[1],
        "QType": qtype_map[int.from_bytes(r[rr_offset:rr_offset+2])],
        "QClass": qclass_map[int.from_bytes(r[rr_offset+2:rr_offset+4])]
    }  


    rr_offset = rr_offset+4
    i = 0

    resp["Answers"] = []
    while i < resp["# Answer RRs"]:
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
            data_raw = r[rr_offset+10:rr_offset+10+record["Data Length"]]
            if record["Type"] in ["A"]:
                outstr = ""
                for b in data_raw[0:-1]:
                    outstr += str(b)
                    outstr += "."
                outstr += str(data_raw[-1])
                record["Data"] = outstr

            elif record["Type"] in ["CNAME", "MB", "MD", "MF", "MG", "MINFO", "MR", "NSDNAME", "PTR", ]:
                record["Data"] = parse_domain(data_raw)

            elif record["Type"] == "MX":

                record["Data"] = { 
                    "Preference": int.from_bytes(data_raw[0:2]), 
                    "Mail Exchange": parse_domain(data_raw[2:-2]+r[data_raw[-1]:-1])
                    }

            elif record["Type"] == "SOA":
                record["Data"] = data_raw # todo: implement parsing

            elif record["Type"] == "WKS":
                record["Data"] = data_raw # todo: implement parsing

            else:
                record["Data"] = data_raw
            rr_offset = rr_offset+10+record["Data Length"]
            resp["Answers"] += [record]
            i += 1

    return resp


#myresponse = query_domain("google.com","1.1.1.1","A",53)[0]

#pprint.pp(parse_response(myresponse))

print(construct_header({"ID":299, "QR":"Query", "OPCODE":"QUERY"}))
