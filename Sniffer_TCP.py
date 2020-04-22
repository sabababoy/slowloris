import socket
import struct
import asyncio

class Part_of_segment:
	def __init__(self, src_ip, dst_ip, sport, dport, ack, seq, flags):
		self.dst_ip = dst_ip
		self.src_ip = src_ip
		self.src_port = sport
		self.dst_port = dport
		self.ack = ack
		self.seq = seq
		self.flags = flags

class Sniffer():

	def __init__(self, ip):
			self.TCP_stack = list()
			self.stop = False
			self.ip = ip

	def stop(self):
		self.stop = Start

	def reset_stack():
		self.TCP_stack = list()

	def get_mac_addr(self, bytes_addr):
		bytes_str = map('{:02x}'.format, bytes_addr)
		mac_addr = ':'.join(bytes_str).upper()

	def ethernet_frame(self, data):
		dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
		return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

	def ipv4_packet(self, data):
		version_header_length = data[0]
		version = version_header_length >> 4
		header_length = (version_header_length & 15) * 4
		ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
		return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

	def ipv4(self, addr):
		return '.'.join(map(str, addr))

	def tcp_segment(self, data):
		(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
		offset = (offset_reserved_flags >> 12) * 4
		flag_urg = (offset_reserved_flags & 32) >> 5
		flag_ack = (offset_reserved_flags & 16) >> 4
		flag_psh = (offset_reserved_flags & 8) >> 3
		flag_rst = (offset_reserved_flags & 4) >> 2
		flag_syn = (offset_reserved_flags & 2) >> 1
		flag_fin = offset_reserved_flags & 1
		return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


	async def sniff(self):

		connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		global TCP_stack
		
		while not self.stop:
			raw_data, addr = connection.recvfrom(65535)
			dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)

			captured = list()

			await asyncio.sleep(0)
			if eth_proto == 8:
				(version, header_length, ttl, proto, src, target, data) = self.ipv4_packet(data)

				src_ip = src
				dst_ip = target

				if proto == 6 and src != self.ip:

					(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = self.tcp_segment(data)

					ack = acknowledgement
					seq = sequence
					sp = src_port
					dp = dest_port
					flags = {'U': flag_urg, 'A': flag_ack, 'P': flag_psh, 'R': flag_rst, 'S': flag_syn, 'F': flag_fin}

					seg = Part_of_segment(src_ip, dst_ip, sp, dp, ack, seq, flags)

					if seg not in captured:
						self.TCP_stack.append(seg)
						captured.append(seg)
					#for i in self.TCP_stack:
						#print('DST IP: {}'.format(i.dst_ip))
						#print('DST PORT: {}'.format(i.dst_port))
						#print('SRC IP: {}'.format(i.src_ip))
						#print('SRC PORT: {}'.format(i.src_port))
						#print('ACK: {}'.format(i.ack))
						#print('SEQ: {}'.format(i.seq))
						#print('FLAGS: {}'.format(i.flags))



