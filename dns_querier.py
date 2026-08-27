import socket
import pprint
from helper_functions import *
from definition_maps import *

dns_db = {
    "google.com": 
    {
        "Type": "Query",
        "Class": "IN",
        "TTL": 300,
        "Data": "1.1.1.1",
        "Data Length": 4 # 4 octets
    }
}



def format_domain(s):
    spl = s.split(".")
    outbytes = []
    for section in spl:
        outbytes += [len(section)]
        for c in section:
            outbytes += [ord(c)]
    outbytes += [0] # null octet for the root
    return outbytes

def construct_query_packet(d,header,qtype):
    packet = []
    packet += construct_header(header)
    packet += format_domain(d) # add question
    packet += [0, qtype_map_inv[qtype]] # add QTYPE
    packet += [0, qclass_map_inv["IN"]] # add QCLASS
    return packet

def construct_header(h):
    ch = [] # ch for constructed header
    ch += [((h["Transaction ID"] & 65535) >> 8), (h["Transaction ID"] & 255)] # 16 bit ID

    # Create 16 bit flags section
    flags = [0, 0]
    if h["QR"] == "Query":
        flags[0] += (0<<8)
    elif h["QR"] == "Response":
        flags[0] += (1<<7)
    else:
        raise Exception("QR value of "+h["QR"]+" is invalid. Must be 'Query' or 'Response'.")
    if h["OPCODE"] == "QUERY":
        flags[0] += (0b0000) << 3
    elif h["OPCODE"] == "IQUERY":
        flags[0] += (0b0001) << 3
    elif h["OPCODE"] == "STATUS":
        flags[0] += (0b0010) << 3
    else:
        raise Exception("OPCODE value of "+h["OPCODE"]+" is invalid. Must be QUERY, IQUERY or STATUS.")

    flags[0] += (int(h["AA"]) << 2)
    flags[0] += (int(h["TC"]) << 1)
    flags[0] += (int(h["RD"]))
    flags[1] += (int(h["RA"]) << 7)
    flags[1] += (int(h["Z"]) << 6)
    flags[1] += rcode_map_inv[h["RCODE"]]

    ch += flags

    # Number of questions, answers, name servers and additional
    ch += [0, h["Num Questions"]]
    ch += [0, h["Num Answer RRs"]]
    ch += [0, h["Num Name Server RRs"]]
    ch += [0, h["Num Additional RRs"]]

    return ch

def construct_rr(rr):
    crr = []
    crr += format_domain(rr["Domain"])
    crr += [0, qtype_map_inv[rr["Type"]]]
    crr += [0, qclass_map_inv[rr["Class"]]]
    crr += [0,0,0,rr["TTL"]]
    crr += [0, rr["Data Length"]]
    crr += rr["Data"]
    return crr


def query_domain(d, ip, qtype="A", header=dict(), port=53):

    h = DEFAULT_QUERY_HEADER
    for k in header:
        h[k] = header[k]

    packet = construct_query_packet(d,h,qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(bytes(packet), (ip,port))
    r = s.recvfrom(1024)
    return r[0]

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

def parse_query(q):
    parsed_question = parse_domain(q[12:-1])

    q_offset = 12+parsed_question[0]+1

    resp = {
        "Transaction ID": q[0:2],
        "Flags": {
            "QR": q[2] >> 7,
            "OPCODE": opcode_map[(q[2] & 0b01111000) >> 3],
            "AA": bool((q[2] & 0b00000100) >> 2),
            "TC": bool((q[2] & 0b00000010) >> 1),
            "RD": bool(q[2] & 0b00000001),
            "RA": bool((q[3] & 0b10000000) >> 7),
            "Z": (q[3] & 0b01110000) >> 4,
            "RCODE": rcode_map[q[3] & 0b00001111]
        },
        "# Questions": (q[4]<<8)+q[5],
        "# Answer RRs": (q[6]<<8)+q[7],
        "# Authority RRs": (q[8]<<8)+q[9],
        "# Additional RRs": (q[10]<<8)+q[11],
        "Question": parsed_question[1],
        "QType": qtype_map[int.from_bytes(q[q_offset:q_offset+2])],
        "QClass": qclass_map[int.from_bytes(q[q_offset+2:q_offset+4])]
    }  

    return resp

def parse_response(r):
    parsed_question = parse_domain(r[12:-1])

    resp = parse_query(r)

    rr_offset = 12+parsed_question[0]+1+4
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


def send_response(query): 
    parsedq = parse_query(query)
    parsedq["Answers"] = []
    for parsedq["Question"] in dns_db:
        record = dict()
        record["Domain"] = parsedq["Question"] # This needs to be the domain pointer. Fixed?
        record["Type"] = dns_db[parsedq["Question"]]["Type"]
        record["Class"] = dns_db[parsedq["Question"]]["Class"]
        record["TTL"] = dns_db[parsedq["Question"]]["TTL"]
        record["Data Length"] = dns_db[parsedq["Question"]]["Data Length"]
        record["Data"] = dns_db[parsedq["Question"]]["Data"]
        parsedq["Answers"] += [record]
    print(parsedq)

    construct_query_packet(parsedq["Question"], parsedq, parsedq["QType"])


send_response(bytes(construct_query_packet("google.com", DEFAULT_QUERY_HEADER,"A")))


'''
server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_sock.bind(('', 54))

while True:

    message, address = server_sock.recvfrom(1024)
    send_response(message)
    server_sock.sendto(message, address) 

'''

'''
myresponse = query_domain("google.com","1.1.1.1")
pprint.pp(parse_response(myresponse))
'''
