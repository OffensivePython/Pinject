import socket
import struct
import sys
from optparse import OptionParser

def checksum(data):
        s = 0
	n = len(data) % 2
	for i in range(0, len(data)-n, 2):
		s+= ord(data[i]) + (ord(data[i+1]) << 8)
	if n:
		s+= ord(data[i+1])
	while (s >> 16):
		s = (s & 0xFFFF) + (s >> 16)
	s = ~s & 0xffff
	return s

class ip(object):
	def __init__(self, source, destination):
		self.version = 4
		self.ihl = 5 # Internet Header Length
		self.tos = 0 # Type of Service
		self.tl = 0 # total length will be filled by kernel
		self.id = 54321
		self.flags = 0
		self.offset = 0
		self.ttl = 255
		self.protocol = socket.IPPROTO_TCP
		self.checksum = 0 # will be filled by kernel
		self.source = socket.inet_aton(source)
		self.destination = socket.inet_aton(destination)
	def pack(self):
		ver_ihl = (self.version << 4) + self.ihl
		flags_offset = (self.flags << 13) + self.offset
		ip_header = struct.pack("!BBHHHBBH4s4s",
					ver_ihl,
					self.tos,
					self.tl,
					self.id,
					flags_offset,
					self.ttl,
					self.protocol,
					self.checksum,
					self.source,
					self.destination)
		return ip_header

class tcp(object):
	def __init__(self, srcp, dstp):
		self.srcp = srcp
		self.dstp = dstp
		self.seqn = 0
		self.ackn = 0
		self.offset = 5 # Data offset: 5x4 = 20 bytes
		self.reserved = 0
		self.urg = 0
		self.ack = 0
		self.psh = 0
		self.rst = 0
		self.syn = 1
		self.fin = 0
		self.window = socket.htons(5840)
		self.checksum = 0
		self.urgp = 0
		self.payload = ""
	def pack(self, source, destination):
		data_offset = (self.offset << 4) + 0
		flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
		tcp_header = struct.pack('!HHLLBBHHH', 
					 self.srcp, 
					 self.dstp, 
					 self.seqn, 
					 self.ackn, 
					 data_offset, 
					 flags,  
					 self.window,
					 self.checksum,
					 self.urgp)
		#pseudo header fields
		source_ip = source
		destination_ip = destination
		reserved = 0
		protocol = socket.IPPROTO_TCP
		total_length = len(tcp_header) + len(self.payload)
		# Pseudo header
		psh = struct.pack("!4s4sBBH",
			  source_ip,
			  destination_ip,
			  reserved,
			  protocol,
			  total_length)
		psh = psh + tcp_header + self.payload
		tcp_checksum = checksum(psh)
		tcp_header = struct.pack("!HHLLBBH",
				  self.srcp,
				  self.dstp,
				  self.seqn,
				  self.ackn,
				  data_offset,
				  flags,
				  self.window)
		tcp_header+= struct.pack('H', tcp_checksum) + struct.pack('!H', self.urgp)
		return tcp_header
def main():
	parser = OptionParser()
	parser.add_option("-s", "--src", dest="src", type="string",
					  help="Source IP address", metavar="IP")
	parser.add_option("-d", "--dst", dest="dst", type="string",
					  help="Destination IP address", metavar="IP")
	options, args = parser.parse_args()
	if options.dst == None:
		parser.print_help()
		sys.exit()
	else:
		dst_host = socket.gethostbyname(options.dst)
	if options.src == None:
		# get the current Network Interface
		src_host = socket.gethostbyname(socket.gethostname())
	else:
		src_host = options.src

	print("[+] Local Machine: %s"%src_host)
	print("[+] Remote Machine: %s"%dst_host)
	s = socket.socket(socket.AF_INET, 
			  socket.SOCK_RAW, 
			  socket.IPPROTO_RAW)
	print("[+] Raw scoket created")
	data = "TEST!!"
	print("[+] Data to inject: %s"%data)
	# IP Header
	print("[+] Constructing IP Header")
	ipobj = ip(src_host, dst_host)
	iph = ipobj.pack()
	# TCP Header
	print("[+] Constructing TCP Header")
	tcpobj = tcp(1234, 80)
	tcpobj.payload = data
	tcph = tcpobj.pack(ipobj.source,
                       ipobj.destination) # tcp header
	# Packet Injection
	packet = iph + tcph + data
	s.sendto(packet, (dst_host, 0))
	print("[+] Packet Injected!")
if __name__=="__main__":
	main()
