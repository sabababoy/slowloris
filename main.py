import TCPackets
import sniffer_TCP
import socket
import random

sniffer = sniffer_TCP.Sniffer()

async def send_syn():

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	src_ip = ''
	src_port = None
	dst_ip = ''
	dst_port = None
	flags = 0b0000010 #SYN flag

	packet = TCPackets.TCPPacket(src_ip, src_port, dst_ip, dst_port, flags)

	for i in range(1000):

		s.sendto(packet, (dst_ip, dst_port))

		packet.seq = random.randint(0, 4294967295)