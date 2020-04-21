import TCPackets
import Sniffer_TCP
import socket
import random
import asyncio

src_ip = ''
src_port = random.randint(0, 65535)
dst_ip = ''
dst_port = None
sniffer = Sniffer_TCP.Sniffer(src_ip)
keep_connection = []

class Connection():
	def __init__(self, src_ip, src_port, ack, seq):
		self.src_ip = src_ip
		self.src_port = src_port
		self.ack = ack
		self.seq = seq


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
		s.sendto(packet.build(), (dst_ip, dst_port))
		packet.seq = random.randint(0, 4294967295)
		packet.src_port = random.randint(0, 65535)


async def connect():

	global sniffer
	global src_ip
	global src_port
	global dst_ip
	global dst_port
	global keep_connection

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	while True:

		await asyncio.sleep(0)

		if sniffer.TCP_stack:

			response_packet = sniffer.TCP_stack[0]

			if response_packet.flags['S'] and response_packet.flags['A']:
				flags = 0b00010000 #ACK flag
				packet = TCPackets.TCPPacket(src_ip, response_packet.dst_port, dst_ip, dst_port, flags)
				packet.seq = response_packet.ack
				packet.ack = response_packet.seq + 1
				s.sendto(packet.build(), (dst_ip, dst_port))
				con = Connection(src_ip, packet.src_port, packet.ack, packet.seq)
				keep_connection.append(con)
				packet.flags = 0b00011000 #ACK and PSH
				s.sendto(packet.build() + ('GET /?{} HTTP/1.1\r\n'.format(random.randint(0, 2000))).encode('utf-8'), (dst_ip, dst_port))
				sniffer.TCP_stack.pop(0)


		
		
				

async def main_loop():
	t1 = asyncio.create_task(send_syn())
	t2 = asyncio.create_task(connect())
	t3 = asyncio.create_task(sniffer.sniff())


	await asyncio.gather(t1, t2, t3)


asyncio.run(main_loop())




