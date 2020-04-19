import struct
import socket
import array

def chksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

class TCPPacket:
	def __init__(self,
				 src_host,
				 src_port,
				 dst_host,
				 dst_port,
				 flags = 0):
		self.src_host = src_host
		self.src_port = src_port
		self.dst_host = dst_host
		self.dst_port = dst_port
		self.ack = 0
		self.seq = 0
		self.flags = flags

	def build(self):
		packet = struct.pack(
			'!HHIIBBHHH',
			self.src_port,  # Source Port
			self.dst_port,  # Destination Port
			self.seq,              # Sequence Number
			self.ack,              # Acknoledgement Number
			5 << 4,         # Data Offset
			self.flags,     # Flags
			8192,           # Window
			0,              # Checksum (initial value)
			0               # Urgent pointer
		)

		p_hdr = struct.pack('!4s4sHH', socket.inet_aton(self.src_host), socket.inet_aton(self.dst_host), socket.IPPROTO_TCP, len(packet))

		checksum = chksum(p_hdr + packet)

		packet = packet[:16] + struct.pack('H', checksum) + packet[18:]

		return packet
