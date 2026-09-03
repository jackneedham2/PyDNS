# These definitions all taken from rfc1035

opcode_map = {
    0:"QUERY", 
    1:"IQUERY", 
    2:"STATUS"
}
rcode_map = {
    0: "No Error", 
    1: "Format Error", 
    2: "Server Failure", 
    3: "Name Error", 
    4: "Not Implemented", 
    5: "Refused"
}
qtype_map = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    252: "AXFR",
    253: "MAILB",
    254: "MAILA",
    255: "*"
}
qclass_map = {
    1: "IN",
    2: "CS",
    3: "CH",
    4: "HS",
    255: "*"
}

qtype_map_inv = {v: k for k, v in qtype_map.items()}
qclass_map_inv = {v: k for k, v in qclass_map.items()}
rcode_map_inv = {v: k for k, v in rcode_map.items()}

type_formats_map = {
    "domain": ["CNAME","MB","MD","MF", "MG", "MINFO","MR"],
    "other": ["HINFO"]
}


DEFAULT_QUERY_HEADER = {
    "Transaction ID":0x2222,
    "Flags": {
        "QR":"Query", 
        "OPCODE":"QUERY",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": False,
        "Z": 0,
        "RCODE": "No Error"
    }, 
    "Num Questions": 1,
    "Num Answer RRs": 0,
    "Num Authority RRs": 0,
    "Num Additional RRs": 0
}

SAMPLE_QUERY_BYTES  = bytes([0x94, 0xff, 0x3c, 0x4c, 0xd3, 0x97, 0xd0, 0x11, 0xe5, 0xd6, 0x55, 0x72, 0x8, 0x0, 0x45, 0x0, 0x0, 0x38, 0x99, 0xf3, 0x0, 0x0, 0x40, 0x11, 0x0, 0x0, 0xa, 0x2c, 0xaf, 0x5d, 0x1, 0x1, 0x1, 0x1, 0xf7, 0x9e, 0x0, 0x35, 0x0, 0x24, 0xbb, 0xc0, 0x22, 0x22, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1])