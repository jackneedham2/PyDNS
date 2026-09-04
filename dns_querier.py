import socket
import pprint
from helper_functions import *
from definition_maps import *
import struct 
dns_db = {
    "google.com": 
    {
        "Type": "A",
        "Class": "IN",
        "TTL": 300,
        "Data": "1.1.1.1",
        "Data Length": 4 # 4 octets
    },
    "yahoo.net": {
        "Type": "A",
        "Class": "IN",
        "TTL": 300,
        "Data": "13.248.158.7",
        "Data Length": 4 # 4 octets
    }
}

# Encoding

def encode_domain(s):
    spl = s.split(".") # split into an array
    outbytes = []
    for section in spl:
        outbytes += [len(section)]
        for c in section:
            outbytes += [ord(c)]
    outbytes += [0] # null octet for the root
    return outbytes

'''
    {
            "QR": "Query" if (f >> 15 == 0) else "Response",
            "OPCODE": opcode_map[(f >> 11) & 15],
            "AA": bool((f >> 10) & 1),
            "TC": bool((f >> 9) & 1),
            "RD": bool((f >> 8) & 1),
            "RA": bool((f >> 7) & 1),
            "Z": (f >> 4) & 7,
            "RCODE": rcode_map[f & 15]
    }
'''



def encode_header(h):

    ch = struct.pack(">H", h["Transaction ID"])

    # Create 16 bit flags section

    flags = [0, 0]
    if h["Flags"]["QR"] == "Query":
        flags[0] += (0<<8)
    elif h["Flags"]["QR"] == "Response":
        flags[0] += (1<<7)
    else:
        raise Exception("QR value of "+str(h["Flags"]["QR"])+" is invalid. Must be 'Query' or 'Response'.")

    if h["Flags"]["OPCODE"] == "QUERY":
        flags[0] += 0 << 3
    elif h["Flags"]["OPCODE"] == "IQUERY":
        flags[0] += 1 << 3
    elif h["Flags"]["OPCODE"] == "STATUS":
        flags[0] += 2 << 3
    else:
        raise Exception("OPCODE value of "+str(h["Flags"]["OPCODE"])+" is invalid. Must be QUERY, IQUERY or STATUS.")

    flags[0] += (int(h["Flags"]["AA"]) << 2)
    flags[0] += (int(h["Flags"]["TC"]) << 1)
    flags[0] += (int(h["Flags"]["RD"]))
    flags[1] += (int(h["Flags"]["RA"]) << 7)
    flags[1] += (int(h["Flags"]["Z"]) << 6)
    flags[1] += rcode_map_inv[h["Flags"]["RCODE"]]

    ch += bytes(flags)

    # Number of questions, answers, name servers and additional

    ch += struct.pack(">H", h["Num Questions"])
    ch += struct.pack(">H", h["Num Answer RRs"])
    ch += struct.pack(">H", h["Num Authority RRs"])
    ch += struct.pack(">H", h["Num Additional RRs"])

    return ch

def encode_rr(rr):
    crr = []
    crr += encode_domain(rr["Domain"])
    crr += [0, qtype_map_inv[rr["Type"]]]
    crr += [0, qclass_map_inv[rr["Class"]]]
    crr += [0,0,0,rr["TTL"]]
    crr += [0, rr["Data Length"]]
    crr += rr["Data"]
    return crr

def encode_query(d,header,qtype):
    packet = []
    packet += encode_header(header)
    packet += encode_domain(d) # add question
    packet += [0, qtype_map_inv[qtype]] # add QTYPE
    packet += [0, qclass_map_inv["IN"]] # add QCLASS
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
    print(f)
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
    s.sendto(bytes(packet), (ip,port))
    r = s.recvfrom(1024)
    return r[0]


def send_response(query):
    try:
        decodedq = decode_query(query)
        decodedq["Answers"] = []

        record = dict()

        if decodedq["Question"] in dns_db:
            record["Domain"] = decodedq["Question"] # This needs to be the domain pointer. Fixed?
            record["Type"] = dns_db[decodedq["Question"]]["Type"]
            record["Class"] = dns_db[decodedq["Question"]]["Class"]
            record["TTL"] = dns_db[decodedq["Question"]]["TTL"]
            record["Data Length"] = dns_db[decodedq["Question"]]["Data Length"]
            record["Data"] = dns_db[decodedq["Question"]]["Data"]
            decodedq["Answers"] += [record]
            decodedq["Num Answer RRs"] = 1
            response_packet = bytes(encode_query(decodedq["Question"], decodedq, decodedq["QType"]))

        else:
            r = (decode_response(send_query(decodedq["Question"], "1.1.1.1")))
            dns_db[decodedq["Question"]] = {
                "Type": "A",
                "Class": "IN",
                "TTL": 300,
                "Data": r["Answers"][0]["Data"],
                "Data Length": 4 # 4 octets
            }
            return send_response(query)

        # add answers in

        #this is a bad way to  do it

        for a in decodedq["Answers"]:
            response_packet += bytes(encode_domain(a["Domain"]))
            response_packet += struct.pack(">h", qtype_map_inv[a["Type"]])
            response_packet += struct.pack(">h", qclass_map_inv[a["Class"]])
            response_packet += struct.pack(">I", a["TTL"])
            response_packet += struct.pack(">h", a["Data Length"])
            if a["Type"] == "A":
                for octet in a["Data"].split('.'):
                    response_packet += struct.pack('B', int(octet))



        return response_packet
    except:
        return 0


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


test_flags_decoded = {'QR': 'Response',
           'OPCODE': 'QUERY',
           'AA': True,
           'TC': True,
           'RD': True,
           'RA': False,
           'Z': 1,
           'RCODE': 'Format Error'}

test_flags_encoded = 33152

print(decode_flags(encode_flags(test_flags_decoded)))


#myresponse = send_query("google.com","1.1.1.1")

#pprint.pp(decode_response(myresponse))
