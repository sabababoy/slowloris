import struct
import socket

def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

class TCPPacket:
	def __init__(self,
				 src_host:  str,
				 src_port:  int,
				 dst_host:  str,
				 dst_port:  int,
				 flags:     int = 0):
		self.src_host = src_host
		self.src_port = src_port
		self.dst_host = dst_host
		self.dst_port = dst_port
		self.flags = flags

	def build(self) -> bytes:
		packet = struct.pack('!HHIIBBHHH', 
							 self.src_port, 
							 self.dst_host, 
							 0, 
							 0, 
							 5 << 4, 
							 self.flags, 
							 8192, 
							 0, 
							 0)

		p_hdr = struct.pack('!4s4sHH', socket.inet_aton(src_host), socket.inet_aton(dst_host), socket.IPPROTO_TCP, len(packet))

		checksum = chksum(p_hdr + packet)

		packet = packet[:16] + checksum + packet[18:]

		return packet
