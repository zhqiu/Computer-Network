# -*- coding: utf-8 -*-
import socket
import struct
import binascii

device_info = {'eth0':'00:0c:29:f2:9d:f7','eth1':'00:0c:29:f2:9d:01'}
arp_table = {'192.168.1.1':'00:0c:29:3f:c9:21',
		'192.168.0.1':'00:0c:29:bc:b8:e6'}
routing_table = {'192.168.2.2':['192.168.1.1','255.255.255.0','eth1'],
		'192.168.0.1':['192.168.0.1','255.255.255.0','eth0']}

def eth_addr(a):
	b="%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"%(ord(a[0]),ord(a[1]),ord(a[2]),ord(a[3]),ord(a[4]),ord(a[5]))
	return b

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
			gateway = routing_table[str(d_addr)][0]
			eth = routing_table[str(d_addr)][2]
			new_dst_mac = arp_table[gateway]
			new_src_mac = device_info[eth]
			print 'new dst mac: '+new_dst_mac
			print 'new src mac: '+new_src_mac
			eth_header = struct.pack('!6s6s2s', binascii.unhexlify(new_dst_mac.replace(':','')), binascii.unhexlify(new_src_mac.replace(':','')), '\x08\x00')
	
			sendSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
			sendSocket.bind((eth, socket.htons(0x0800)))
			new_packet = eth_header + packet[eth_length:]			
			bytes = sendSocket.send(new_packet)
			print 'Have transmit '+str(bytes)+' bytes'
	else:
		print 'It\'s NOT my packet'
		
	
