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
rSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rSocket.bind(("eth0", socket.htons(0x0800)))  # change nerwork card if you need
# build frame header, which contains dst mac, src mac and protocol type(IPv4)
# you should this the following mac addr based on your device
frameHeader = struct.pack("!6s6s2s",'\x00\x0c\x29\x3f\xc9\x2b','\x00\x0c\x29\x1d\x6f\x5b','\x08\x00')
# build IP header
saddr = socket.inet_aton("192.168.2.2")       # src ip, change if you need
daddr = socket.inet_aton("192.168.0.1")       # dst ip, change if you need
ipHeader = struct.pack("!BBHHHBBH4s4s", (4<<4)+5, 0, 28, 
						0, 0, 64, 1, 0, saddr, daddr)
ipHeader = struct.pack("!BBHHHBBH4s4s", (4<<4)+5, 0, 28, 
						0, 0, 64, 1, ip_headchecksum(ipHeader), saddr, daddr)
# build ICMP packet
icmp = struct.pack("!BBHHH", 0, 0, 0, 0, 0)  # ping reply
icmp = struct.pack("!BBHHH", 0, 0, checksum(icmp), 0, 0)
# build and send the whole packet
packet_reply = frameHeader + ipHeader + icmp

# set a socket to listen
lSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

while True:
	packet = lSocket.recvfrom(2048)
	packet = packet[0]
	ipheader = packet[14:20+14]
	iph = struct.unpack('!BBHHHBBH4s4s', ipHeader)
	if iph[6] == 1:        # it's an icmp packet
		rSocket.send(packet_reply)

