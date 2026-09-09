import socket
import pprint
from definition_maps import *
import struct 


# Encoding

def encode_domain(s):
    spl = s.split(".") # split into an array
    outbytes = bytes()
    for section in spl:
        outbytes += struct.pack("!B", len(section))
        for c in section:
            outbytes += struct.pack("!B", ord(c))
    outbytes += struct.pack("!B", 0) # null octet for the root
    return outbytes

def encode_flags(f):
    encoded = int()
    encoded += (1 << 15) if f["QR"] == "Response" else 0
    encoded += (opcode_map_inv[f["OPCODE"]] << 11)
    encoded += (int(f["AA"]) << 10)
    encoded += (int(f["TC"]) << 9)
    encoded += (int(f["RD"]) << 8)
    encoded += (int(f["RA"]) << 7)
    encoded += (f["Z"] << 4)
    encoded += rcode_map_inv[f["RCODE"]]
    return encoded

def encode_header(h):
    ch = struct.pack(">H", h["Transaction ID"])

    # Create 16 bit flags section
    ch += struct.pack(">H", encode_flags(h["Flags"]))

    # Number of questions, answers, name servers and additional
    ch += struct.pack(">H", h["Num Questions"])
    ch += struct.pack(">H", h["Num Answer RRs"])
    ch += struct.pack(">H", h["Num Authority RRs"])
    ch += struct.pack(">H", h["Num Additional RRs"])

    return ch

def encode_query(d,header,qtype):
    packet = bytes()
    packet += encode_header(header)
    packet += encode_domain(d) # add question
    packet += struct.pack("!H", qtype_map_inv[qtype]) # add QTYPE
    packet += struct.pack("!H", qclass_map_inv["IN"]) # add QCLASS
    return packet

# Decoding

def decode_domain(d):
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

def decode_flags(f):
    return {
            "QR": "Query" if (f >> 15 == 0) else "Response",
            "OPCODE": opcode_map[(f >> 11) & 15],
            "AA": bool((f >> 10) & 1),
            "TC": bool((f >> 9) & 1),
            "RD": bool((f >> 8) & 1),
            "RA": bool((f >> 7) & 1),
            "Z": (f >> 4) & 7,
            "RCODE": rcode_map[f & 15]
    }

def decode_query(q):
    decoded_question = decode_domain(q[12:])
    q_offset = 12+decoded_question[0]+1
    header_struct = struct.Struct("!HHHHHH")
    header = header_struct.unpack(q[0:12])
    return {
        "Transaction ID": header[0],
        "Flags": decode_flags(header[1]),
        "Num Questions": header[2],
        "Num Answer RRs": header[3],
        "Num Authority RRs": header[4],
        "Num Additional RRs": header[5],
        "Question": decoded_question[1],
        "QType": qtype_map[struct.unpack("!H",q[q_offset:q_offset+2])[0]],
        "QClass": qclass_map[struct.unpack("!H",q[q_offset+2:q_offset+4])[0]]
    }

def decode_response(r):

    # Decode header + query
    decoded_query = decode_query(r)
    records_offset = 18 + len(decoded_query["Question"])
    records = r[records_offset:]
    decoded_query["Answers"] = []


    # Decode answer resource records    
    for answer in range(decoded_query["Num Answer RRs"]):

        decoded_record = dict()

        if (struct.unpack("!H",records[0:2])[0] >> 14):
            question_pointer = struct.unpack("!H", records[0:2])[0] ^ (0b11 << 14)
            decoded_record["Domain"] = decode_domain(r[question_pointer:question_pointer+len(decoded_query["Question"])+2])[1]
            records = records[2:]

        else:
            decoded_record["Domain"] = decode_domain(r[0:-1])[1]
            records = records[len(decoded_record["Domain"])+1:]

        record_struct = struct.Struct("!HHIH")
        record_unpacked = record_struct.unpack(records[0:10])

        decoded_record["Type"] = qtype_map[record_unpacked[0]]
        decoded_record["Class"] = qclass_map[record_unpacked[1]]
        decoded_record["TTL"] = record_unpacked[2]
        decoded_record["Data Length"] = record_unpacked[3]

        match decoded_record["Type"]:
            case "A" | "CNAME"| "MB"| "MD"| "MF"| "MG"| "MINFO"| "MR"| "NSDNAME"| "PTR": 
                a_struct = struct.Struct("!BBBB")
                decoded_record["Data"] = ".".join([str(x) for x in a_struct.unpack(records[10:10+decoded_record["Data Length"]])])
            case _:
                decoded_record["Data"] = records[10:10+decoded_record["Data Length"]]

        records = records[10+decoded_record["Data Length"]:]
        decoded_query["Answers"] += [decoded_record]


    return decoded_query


# Send + respond

def send_query(d, ip, qtype="A", header=dict(), port=53):
    h = DEFAULT_QUERY_HEADER
    for k in header:
        h[k] = header[k]

    packet = encode_query(d,h,qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(packet, (ip,port))
    r = s.recvfrom(1024)
    return r[0]

myresponse = send_query("google.com","1.1.1.1")
pprint.pp(decode_response(myresponse))
