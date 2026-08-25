import socket

class DNSQuerier:
    header = [
        0,0, # Transaction ID
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
        return outbytes

    def create_query_packet(self, d):
        packet = []
        packet += self.header
        packet += self.format_domain(d)
        packet += [0,0]
        packet += [1, 0] # Type: PTR Record
        packet += [1, 0] # QCLASS = IN
        packet += [0x80, 0x1]
        return packet

    def query_domain(self,d, ip, port):
        packet = self.create_query_packet(d)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(bytes(packet), (ip,port))
        d = s.recvfrom(1024)
        return d



my_querier = DNSQuerier()
print(my_querier.query_domain("google.com","1.1.1.1",53))