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