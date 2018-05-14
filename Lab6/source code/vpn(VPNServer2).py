# -*- coding: utf-8 -*-

import socket, struct, binascii

IP_VERSION = 4

device_info = {'eth0':'00:0c:29:f2:0a:0c','eth1':'00:0c:29:f2:0a:16'}
arp_table = {'172.0.0.1':'00:0c:29:b5:f0:43',
		'10.0.1.2':'00:0c:29:c7:a2:1d'}
routing_table = {'192.168.0.2':['172.0.0.1','255.255.255.0','eth0'],
		'10.0.1.2':['10.0.1.2','255.255.255.0','eth1']}

def eth_addr(a):
	b="%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"%(ord(a[0]),ord(a[1]),ord(a[2]),ord(a[3]),ord(a[4]),ord(a[5]))
	return b

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

def repack_packet(newSrcIp, newDstIp):      # build IP header
	ihl_version = (IP_VERSION << 4) + 5 # Version + Header Length
	tos = 0                             # Type Of Service
	totalLen = 104                       # Total Length
	idMark = 0                          # fragment id
	offset = 0                          # fragment offset
	ttl = 64                            # Time To Live
	proto = 1                           # Protocol (1 means ICMP)
	checkSum = 0                        # Check Sum
	saddr = socket.inet_aton(newSrcIp)      # src ip, change if you need
	daddr = socket.inet_aton(newDstIp)       # dst ip, change if you need
	ipHeader = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, totalLen, 
						idMark, offset, ttl, proto, checkSum, saddr, daddr)
	ipHeader = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, totalLen, 
						idMark, offset, ttl, proto, ip_headchecksum(ipHeader), saddr, daddr)
	return ipHeader 

listenSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

while True:
	packet = listenSocket.recvfrom(65565)
	packet = packet[0]
	eth_length = 14
	eth_header = packet[:eth_length]
	eth = struct.unpack('!6s6sH', eth_header)
	eth_prot = socket.ntohs(eth[2])
	dst_mac = eth_addr(packet[0:6])
	src_mac = eth_addr(packet[6:12])
	print 'Des mac: '+dst_mac+' Src mac: '+src_mac+' Ptotocol: '+str(eth_prot)
	if dst_mac == device_info['eth0'] or dst_mac == device_info['eth1']:
		print 'The packet was sent to ME '
		if eth_prot == 8:
			print 'It\'s a IP protocol'
			ip_header = packet[eth_length:20+eth_length]
			iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
			s_addr = socket.inet_ntoa(iph[8])
			d_addr = socket.inet_ntoa(iph[9])
			print 'Src ip: '+str(s_addr)+' Dst ip: '+str(d_addr)
			if str(d_addr)=='10.0.0.2':   # want to send to another ethnet
				print 'I should pack this packet!'
				newSrcIp = '172.0.0.2' 
				newDstIp = '192.168.0.2'
				addIpHeader = repack_packet(newSrcIp, newDstIp)  # add new ip header
				gateway = routing_table[newDstIp][0]
				eth = routing_table[newDstIp][2]
				new_dst_mac = arp_table[gateway]
				new_src_mac = device_info[eth]
				print 'new dst mac: '+new_dst_mac
				print 'new src mac: '+new_src_mac
				eth_header = struct.pack('!6s6s2s', 
							binascii.unhexlify(new_dst_mac.replace(':','')), 
							binascii.unhexlify(new_src_mac.replace(':','')), '\x08\x00')
				sendSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
				sendSocket.bind((eth, socket.htons(0x0800)))
				new_packet = eth_header + addIpHeader + packet[eth_length:]			
				bytes = sendSocket.send(new_packet)
				print 'Finish repack this packet'
				print 'Have transmit '+str(bytes)+' bytes'
			if str(d_addr)=='172.0.0.2':   # the packet was sent to ME, start to unpack
				ip_header_inner = packet[20+eth_length:40+eth_length]
				iph_inner = struct.unpack('!BBHHHBBH4s4s', ip_header_inner)
				s_addr_inner = socket.inet_ntoa(iph_inner[8])
				d_addr_inner = socket.inet_ntoa(iph_inner[9])
				if d_addr_inner=='10.0.1.2':       # I should unpack this packet
					sendSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
					sendSocket.bind(('eth1', socket.htons(0x0800)))
					eth_header = struct.pack('!6s6s2s',        # dst->src
							binascii.unhexlify('00:0c:29:c7:a2:1d'.replace(':','')), 
							binascii.unhexlify('00:0c:29:f2:0a:16'.replace(':','')), '\x08\x00')
				#	newIpHeader_inner = buildNewIpHeader()
					new_packet = eth_header + packet[eth_length+20:]			
					bytes = sendSocket.send(new_packet)
					print 'Finish unpack this packet'
					print 'Have transmit '+str(bytes)+' bytes'
	else:
		print 'It\'s NOT my packet'
