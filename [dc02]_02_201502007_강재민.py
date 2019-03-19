import socket
import struct

def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x" + ethernet_header[12].hex()
	print("======ethernet header======")
	print("src_mac_address:", ether_src)
	print("dest_mac_address:", ether_dest)
	print("ip_version",ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

def parsing_ip_header(data,size):
	if( size == 20 ):
		ip_header = struct.unpack("!2B3H2c1H4c4c", data)
	else:
		size = size-20
		ip_header = struct.unpack("!2B3H2c1H4c4c"+size+"s", data)
	print("=========ip_header=========")
	print("ip_version: ",int(ip_header[0]/ 16 ))
	print("ip_Legnth: ",ip_header[0] % 16)
	print("differentiated_service_codepoint: ",int(ip_header[1] / 4))
	print("explicit_congestion_notification: ",ip_header[1] % 4) 
	print("Total Length: ",ip_header[2])
	print("identification: ",ip_header[3])
	flag = "{0:0<3b}".format(int(ip_header[4]/4096))
	print("flags: ", "0x{0:0<4x}".format(int(ip_header[4] /4096)))
	print(">>>reserved bit: ", flag[0])
	print(">>>not_fragments: ", flag[1] )
	print(">>>fragments: ",  flag[2] )
	print(">>>fragments_offset: ", str((ip_header[4] % 4096)).format('x') )
	print("Time to live: ", ord(ip_header[5]))
	print("protocol: ", ip_header[6].hex())
	print("header checksum: ", "0x{0:0<4x}".format(ip_header[7]))
	ip_src = convert_ip_address(ip_header[8:12])
	ip_dest = convert_ip_address(ip_header[12:16])
	print("source_ipaddress: ", ip_src)
	print("dest_ip_Addresss: ", ip_dest)
	if(size != 20):
		print("Options: ", ip_header[16])
	return ip_header[6].hex()

def convert_ip_address(data):
	ip_addr = list()
	for i in data:
		ip_addr.append(str(ord(i)))
	ip_addr = ".".join(ip_addr)
	return ip_addr

def check_ip_header_size(data):
	ip_header = struct.unpack("!2B3H2c1H4c4c", data)
	return 4*(int(ip_header[0] % 16))

def parsing_tcp_header(data):
	tcp_header = struct.unpack("!2H2I2B3H", data)
	print("=========tcp_header=========")
	print("src_port: ", int(tcp_header[0]))
	print("dec_port: ", int(tcp_header[1]) )
	print("seq_num: ",tcp_header[2])
	print("ack_num: ",tcp_header[3])
	print("header_len: ", int(tcp_header[4] / 16))
	flag = "{0:0>8b}".format(tcp_header[5])
	print(">>>reserved: ", int((tcp_header[4] % 16)/2) )
	print(">>>nonce: ", (tcp_header[4] % 16) % 2)
	print(">>>cwr: ", flag[0])
	print(">>>urgent: ", flag[2])
	print(">>>ack: ", flag[3])
	print(">>>push: ", flag[4])
	print(">>>reset: ",flag[5])
	print(">>>syn: ", flag[6])
	print(">>>fin: ", flag[7])
	print("window_size_value: ", tcp_header[6])
	print("checksum: ", tcp_header[7])
	print("urgent pointer: ", tcp_header[8])

def parsing_udp_header(data):
	udp_header = struct.unpack("!4H", data)
	print("=========tcp_header=========")
	print("src_port: ", udp_header[0])
	print("dst_port: ", udp_header[1])
	print("leng: ", udp_header[2])
	print("header checksum: ", "0x{0:<4x}".format(udp_header[3]))


print("<<<<<<Packet Capture Start>>>>>>")	
recv_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

i = 0
while 1:
	data = recv_socket.recvfrom(20000)
	i = i+1
	parsing_ethernet_header(data[0][0:14])
	ip_size = check_ip_header_size(data[0][14:34])
	ip_end = 14+ip_size
	protocol = parsing_ip_header(data[0][14:ip_end], ip_size)
	if(protocol == "06"):
		parsing_tcp_header(data[0][ip_end:ip_end+20])	
	if(protocol == "11"):
		parsing_udp_header(data[0][ip_end:ip_end+8])
	print("\n\n <<<Next Packet>>> \n\n")

