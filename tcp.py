#!/usr/bin/env python

"""
Copyright (c) 2016 Dani Tapio. ( 14afajonoso@gmail.com )

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files ( tcplib ), to deal in the tcplib
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the the tcplib is
furnished to do so, subjet to the following conditions:

The above copyright notice and this permission notice shall be included in all copies
or substential portitions of the tcplib.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANI KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""


" we need struct and socket libraries to operate with raw_sockets "
import struct, socket


" checksum(x) function calculates tcp checksum "
def checksum(x):
	s = 0
	" loop taking 2 chars at each round "
	for i in range(0, len(x), 2):
		" s = s + ord of i.th value of x + ord of i+1.th value of x << 8 "
		s += ord(x[i]) + (ord(x[i+1]) << 8)
	s = ( s >> 16 ) + ( s & 0xffff)
	s += (s >> 16)
	s = ~s & 0xffff
	return s


" function to create us ip packet "
" requires destination and source ipv4 addresses, id and fragoff "
def CreateIpPacket(SrcAddr, DestAddr, ip_id, frag_off):
	" ip header "
	ip_ihl		= 5
	ip_ver		= 4 # TODO: implement IPv6
	ip_tos		= 0
	ip_tot_len	= 0 # we are not providing tot len, as kernel will fill this for us
	ip_ttl		= 255
	ip_proto	= socket.IPPROTO_TCP # tcp protocol is being used
	ip_check	= 0 # kernel will fill this also 
	ip_saddr	= socket.inet_aton(SrcAddr)
	ip_daddr	= socket.inet_aton(DestAddr)
	
	ip_ihl_ver	= ( ip_ver << 4 ) + ip_ihl
	
	" ! means network order "
	ip_header	= struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
	return ip_header
	
" function to create us TCP header "
" requires ports, list of flags, window, and sequence numbers as well as urg ptr"
" flags : "
"     fin "
"     syn "
"     rst "
"     psh "
"     ack "
"     urg "
" and userdata also required "
" source and destination addresses are needed for pseudo-headers for checksum "

def CreateTcpPacket(SrcAddr, DestAddr, srcport, dstport, flags, window, seq, ack_seq, urgptr, user_data):
	" 4bit field * size of tcp header = 4 * 5 = 20 bytes "
	tcp_doff		= 5
	" tcp flags "
	tcp_fin			= flags[0]
	tcp_syn			= flags[1]
	tcp_rst			= flags[2]
	tcp_psh			= flags[3]
	tcp_ack			= flags[4]
	tcp_urg			= flags[5]
	
	tcp_window		= socket.htons( window )
	tcp_check		= 0
	tcp_urg_ptr		= urgptr
	tcp_offset_res	= ( tcp_doff << 4) + 0
	tcp_flags		= tcp_fin + ( tcp_syn << 1 ) + (tcp_rst << 2 ) + (tcp_psh << 3 ) + (tcp_ack << 4) + (tcp_urg << 5)
	
	" ! in the pack means network order "
	tcp_header		= struct.pack("!HHLLBBHHH", srcport, dstport, seq, ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, urgptr)

	tcp_check		= checksum(CreatePseudoHeader(SrcAddr, DestAddr, tcp_header, user_data))
	tcp_header		= struct.pack("!HHLLBBHHH", srcport, dstport, seq, ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, urgptr)
	return tcp_header


" requires source address, destination address and tcp header and userdata "
def CreatePseudoHeader(srcaddr, destaddr, tcphdr, userdata):
	srcaddr		= socket.inet_aton( srcaddr )
	destaddr	= socket.inet_aton( destaddr )
	placeholder	= 0
	protocol	= socket.IPPROTO_TCP
	tcp_length	= len(tcphdr) + len(userdata)
	pseudo		= struct.pack("!4s4sBBH", srcaddr, destaddr, placeholder, protocol, tcp_length)
	return pseudo
	
"""
class send is for sending tcp packets.
requires no arguments from user
"""
class TCP:
	
	def __init__(self):
		try:
			" this kind of socket requires root privs. "
			self.socks = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW )
		except Exception as E:
			return ("unable to create sockets! error: %s\n" % str(E))
	
	
	" sendPacket function usage: "

	"""
	params are:
		SrcAddr			= source ip, your ip address
		DestAddr		= destination ip, host ip address
		ip_id			= ip id of the ip header
		frag_off		= fragoff of ip header ( more packets/fragments to come? )
		srcport			= tcp sourceport ( where from do the packets come )
		dstport			= tcp destination port ( where to send packets )
		flags			= list of tcp flags, explained after few lines
		window			= tcp window ( 0 - 5840 )
		seq				= sequencenumber of tcp packet
		ack_seq			= acknowledgment sequence of tcp packet
		urgptr			= urgency ptr
		user_data		= userdata, eg. http etc.
	
	flags of tcp packet:
		fin
		syn
		rst
		psh
		ack
		urg
	
	so, eg. for syn packet, flags list is:
		flags = [ 0, 1, 0, 0, 0, 0 ]
	
	returns 1 or 0
	
	[examplecode]:
	
	import tcp	# import tcp library
	flags = [ 0, 1, 0, 0, 0, 0 ]	# decide flags
	t		= tcp.TCP()				# define t and send packet
	sent 	= t.sendPacket("192.168.100.4", "192.168.100.1", 512, 0, 3136, 80, flags, 456, 412, 0, 0, "")
	if send:
		print "ok, packet sent"
	else:
		print "error, can't send packet!"
	
	[endcode]
	"""
	
	def sendPacket(self, SrcAddr, DestAddr, ip_id, frag_off, srcport, dstport, flags, window, seq, ack_seq, urgptr, user_data):
		try:
			ip_header 	= CreateIpPacket(SrcAddr, DestAddr, ip_id, frag_off)
			tcp_header	= CreateTcpPacket(SrcAddr, DestAddr, srcport, dstport, flags, window, seq, ack_seq, urgptr, user_data)
			packet		= ip_header + tcp_header + user_data
			self.socks.sendto(packet, (DestAddr, 0 ))
			return 1
		except KeyboardInterrupt as E:
			return E

	"""
	recvPacket function is for receiving tcp packets
	requires listening port from user.
	
	returns list of src_port, seq, ack, flags, data
	where src_port is port where from packet was
	seq is tcp sequence number
	ack is tcp acknow. number
	data is the user_data, eg. http
	
	
	[examplecode]:
	
	import tcp			# import tcp library
	t	= tcp.TCP()		# define t
	src_port, seq, ack, flags, data = t.recvPacket(8080)	# listen for packets coming to 8080
	print data	# print incoming data
		
	[endcode]
	"""
	
	def recvPacket(self, port):
		packet		= self.socks.recvfrom(65565)
			
		# packet string from tuple
		packet		= packet[0]
			
		" get the ip header length "
		ip_header	= packet[0:20]
		ip_header	= struct.unpack("!BBHHHBBH4s4s", ip_header)
		version_ihl	= ip_header[0]
		version		= version_ihl >> 4
		ihl			= version_ihl & 0xF
		iph_length	= ihl * 4
		
		" get tcp header "
		tcp_header	= packet[iph_length:iph_length+20]
		tcp_header	= struct.unpack("!HHLLBBHHH", tcp_header)
		
		src_port	= tcph[0]
		dest_port	= tcph[1]
		seq			= tcph[2]
		ack			= tcph[3]
		doff_res	= tcph[4]
		flags		= tcph[5]
		tcph_len	= doff_res >> 4
		
		if dest_port == port:
			h_size 		= iph_length + tcp_length * 4
			data_size 	= len(packet) - h_size
			
			data		= packet[h_size:]
			
			return [src_port, seq, ack, flags, data]

