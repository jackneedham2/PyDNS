import struct

from definition_maps import *
import dns_querier
import copy

# DECODER FUNCTIONS

def decode_flags(b, start, end):
	flags = {
        "QR": "Query" if (b[2] >> 7 == 0) else "Response",
        "OPCODE": opcode_map[(b[2] & 0b01111000) >> 3],
        "AA": bool((b[2] & 0b00000100) >> 2),
        "TC": bool((b[2] & 0b00000010) >> 1),
        "RD": bool(b[2] & 0b00000001),
        "RA": bool((b[3] & 0b10000000) >> 7),
        "Z": (b[3] & 0b01110000) >> 4,
        "RCODE": rcode_map[b[3] & 0b00001111]
    }
	return flags
# runs bytes through the packet map and decodes as required
def decode_bytes(k, b): # k for key and b for bytes
	if isinstance(q_decode_pmap[k][0],str):
		return struct.unpack(q_decode_pmap[k][0], b[q_decode_pmap[k][1]:q_decode_pmap[k][2]])[0]
	else:
		return q_decode_pmap[k][0](b, q_decode_pmap[k][1], q_decode_pmap[k][2])

def decode_packet(b):
	decoded = dict()
	for k in q_decode_pmap:
		decoded[k] = decode_bytes(k, b)

	if decoded["Num Answer RRs"] > 0:
		print("This is a response packet")

	return decoded

def decode_answers(b, start, end):
	return b[start:end]


# ENCODER FUNCTIONS
def encode_flags(b, start, end):
	print(b, start, end)

def encode_bytes(k,b):
	if isinstance(q_encode_pmap[k][0],str):
		print(struct.pack(q_encode_pmap[k][0], b))
		return struct.pack(q_encode_pmap[k][0], b)
	else:
		return bytes(0xFF)
		#return q_decode_pmap[k][0](b, q_decode_pmap[k][1], q_decode_pmap[k][2])


def encode_packet(b):
	encoded = b'00'
	for k in q_encode_pmap:
		encoded += encode_bytes(k, b[k])
	return encoded


# PACKET MAPS 

# Question decode packet map
q_decode_pmap = {
	# Key			  format / function, start, end
	"Transaction ID": [">H", 0, 2],
	"Flags": [decode_flags, 2, 4],
    "Num Questions": [">H", 4, 6],
    "Num Answer RRs": [">H", 6, 8],
    "Num Authority RRs": [">H", 8, 10],
    "Num Additional RRs": [">H", 8, 10],
}

# Answer decode packet map
adecode_pmap = {
}

# Question encode packet map
q_encode_pmap = copy.deepcopy(q_decode_pmap)
q_encode_pmap["Flags"] = [encode_flags, 2, 4]


myheader = {
    "Transaction ID":21621,
    "Flags": {
        "QR":"Query", 
        "OPCODE":"QUERY",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "RCODE": "No Error"
    }, 
    "Num Questions": 1,
    "Num Answer RRs": 1,
    "Num Authority RRs": 0,
    "Num Additional RRs": 0
}
mytest = dns_querier.construct_query_packet("google.com", myheader, "A")
mytest_dict = {'Transaction ID': 257, 'Flags': {'QR': 'Query', 'OPCODE': 'QUERY', 'AA': True, 'TC': True, 'RD': True, 'RA': False, 'Z': 0, 'RCODE': 'No Error'}, 'Num Questions': 1, 'Num Answer RRs': 0, 'Num Authority RRs': 0, 'Num Additional RRs': 0, 'Question': 'google.com', 'QType': 'A', 'QClass': 'IN', 'Answers': []}
print(encode_packet(mytest_dict))

#mybytes = bytes(mytest)
#print(decode_packet(mybytes))
#responsetest = dns_querier.send_response(mybytes)
#responsebytes = bytes(responsetest)
#print(mybytes)
#print(decode_packet(mybytes))
