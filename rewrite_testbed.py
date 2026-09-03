import struct
from definition_maps import *

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

# 12 byte fixed header before question

DNS_query_packet = struct.Struct("!HHHHHH")

print(DNS_query_packet.unpack(SAMPLE_QUERY_BYTES[0:12]))

print(SAMPLE_QUERY_BYTES[12:-1])
decoded_question = (decode_domain(SAMPLE_QUERY_BYTES[12:-1]))
print(SAMPLE_QUERY_BYTES[12+decoded_question[0]+1:-1])

DNS_question_section = struct.Struct("!"+("B"*decoded_question[0])+"HH")
print(len(SAMPLE_QUERY_BYTES[12:-1]))
print(DNS_question_section.unpack(SAMPLE_QUERY_BYTES[12:-1]))
