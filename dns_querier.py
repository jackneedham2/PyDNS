import socket

def string_splitter(s):
    spl = s.split(".")
    outbytes = []
    for section in spl:
        outbytes += [len(section)]
        for c in section:
            outbytes += [ord(c)]
    return outbytes

# One-Shot Multicast DNS Querier.
# Standard DNS packet sent to 244.0.0.251:5353
domain = "_nmos-node._tcp.local"

packet = [

# Header

0,0, # Transaction ID
1,0, # Flags
0,1, # Num questions
0,0, # Num Answer RRs
0,0, # Num Authority RRs
0,0, # Num Additional RRs

    ]

# Add query to end

packet += string_splitter("yahoo.net")
packet += [0,0]
packet += [1, 0] # Type: PTR Record
packet += [1, 0] # QCLASS.
packet += [0x80, 0x1]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(bytes(packet), ("1.1.1.1",53))
d = s.recvfrom(1024)[0]

print(d)

'''
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from socket import inet_ntoa
import json
import requests

def get_req(nodeIP, endpoint):
    return json.loads(requests.get("http://"+nodeIP+endpoint).content)

class MyListener(ServiceListener):

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} updated")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} removed")

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        print(get_req(inet_ntoa(info.addresses[0]), "/x-nmos/node/v1.3/self"))


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_nmos-node._tcp.local.", listener)
try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.close()
    '''