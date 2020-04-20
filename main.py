import TCPackets
import sniffer_TCP
import socket
import random
import asyncio
import threading

sniffer = sniffer_TCP.Sniffer('')
src_ip = ''
src_port = None
dst_ip = ''
dst_port = None

thread = threading.Thread(sniffer.sniff())

async def send_syn():

	global src_ip
	global src_port
	global dst_ip
	global dst_port

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	flags = 0b0000010 #SYN flag

	packet = TCPackets.TCPPacket(src_ip, src_port, dst_ip, dst_port, flags)
	sniffer.ip = src_ip

	for i in range(1):

		s.sendto(packet, (dst_ip, dst_port))

		packet.seq = random.randint(0, 4294967295)

async def keep_connection_open():

	global sniffer
	global src_ip
	global src_port
	global dst_ip
	global dst_port

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	while True:

		if sniffer.TCP_stack:

			response_packet = sniffer.TCP_stack[0]

			if response_packet.flags['S'] and response_packet.flags['A']:
				flags = 0b00010000 #ACK flag
				packet = TCPackets.TCPPacket(src_ip, src_port, dst_ip, dst_port, flags)
				packet.seq = response_packet.ack
				packet.ack = response_packet.syn + 1
				s.sendto(packet, (dst_ip, dst_port))
