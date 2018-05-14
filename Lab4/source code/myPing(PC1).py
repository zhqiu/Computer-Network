# -*- coding: utf-8 -*-
"""
	Author: Qiu Zihao
	Description: Homework of Computer Network
				 implement ping using my mac,ip
"""

import socket, struct

ICMP_ECHO_REQUEST = 8
IP_VERSION = 4

# function to calculate checksum of ip head(copy from blog)
def ip_headchecksum(ip_head):
	checksum = 0
	headlen = len(ip_head)
	i = 0
	while i<headlen:
		temp = struct.unpack("!H", ip_head[i:i+2])[0]
		checksum += temp
		i += 2
	checksum = (checksum>>16) + (checksum&0xffff)
	checksum += checksum>>16

	return (~checksum)&0xffff

# function to calculate checksum of icmp(copy from github)
def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff # Necessary?
        count = count + 2

    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?

    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer 


# crear raw socket
rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rawSocket.bind(("eth0", socket.htons(0x0800)))  # change nerwork card if you need
# build frame header, which contains dst mac, src mac and protocol type(IPv4)
# you should change the following mac addr based on your device
frameHeader = struct.pack("!6s6s2s",'\x00\x0c\x29\xf2\x9d\xf7','\x00\x0c\x29\xbc\xb8\xe6','\x08\x00')
# build IP header
ihl_version = (IP_VERSION << 4) + 5 # Version + Header Length
tos = 0                             # Type Of Service
totalLen = 28                       # Total Length
idMark = 0                          # fragment id
offset = 0                          # fragment offset
ttl = 64                            # Time To Live
proto = 1                           # Protocol (1 means ICMP)
checkSum = 0                        # Check Sum
saddr = socket.inet_aton("192.168.0.1")      # src ip, change if you need
daddr = socket.inet_aton("192.168.2.2")       # dst ip, change if you need
ipHeader = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, totalLen, 
						idMark, offset, ttl, proto, checkSum, saddr, daddr)
ipHeader = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, totalLen, 
						idMark, offset, ttl, proto, ip_headchecksum(ipHeader), saddr, daddr)
# build ICMP packet
icmp = struct.pack("!BBHHH", 8, 0, 0, 0, 0)  # ping request
icmp = struct.pack("!BBHHH", 8, 0, checksum(icmp), 0, 0)
# build and send the whole packet
packet = frameHeader + ipHeader + icmp
rawSocket.send(packet) 

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b

# receive the icmp packet
recSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
 
while True:  
	packet = recSocket.recvfrom(65565)
	
	#packet string from tuple
	packet = packet[0]
	
	#parse ethernet header
	eth_length = 14
	
	eth_header = packet[:eth_length]
	eth = struct.unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])
	print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		
		#now unpack them :)
		iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);

		print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

		#ICMP Packets
		if protocol == 1 :
			print 'Get icmp reply!!!!'
			u = iph_length + eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]

			#now unpack them :)
			icmph = struct.unpack('!BBH' , icmp_header)
			
			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			
			print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
			
			h_size = eth_length + iph_length + icmph_length
			data_size = len(packet) - h_size
		else:
			print 'Other protocol'

