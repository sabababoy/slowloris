import TCPackets
import Sniffer_TCP
import socket
import random
import asyncio

src_ip = ''
src_port = None
dst_ip = ''
dst_port = None
sniffer = Sniffer_TCP.Sniffer(src_ip)


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

async def keep_connection_open():

	global sniffer
	global src_ip
	global src_port
	global dst_ip
	global dst_port

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	while True:
		await asyncio.sleep(0)

		if sniffer.TCP_stack:

			response_packet = sniffer.TCP_stack[0]

			if response_packet.flags['S'] and response_packet.flags['A']:
				flags = 0b00010000 #ACK flag
				packet = TCPackets.TCPPacket(src_ip, src_port, dst_ip, dst_port, flags)
				packet.seq = response_packet.ack
				packet.ack = response_packet.seq + 1
				s.sendto(packet.build(), (dst_ip, dst_port))
				sniffer.TCP_stack.pop(0)

async def main_loop():
	t1 = asyncio.create_task(send_syn())
	t2 = asyncio.create_task(keep_connection_open())
	t3 = asyncio.create_task(sniffer.sniff())

	await asyncio.gather(t1, t2, t3)


asyncio.run(main_loop())




