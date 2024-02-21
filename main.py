import struct
import socket
import textwrap

TAB_1 = '\t -- '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest, src, proto, data = get_ethernet_frame(raw_data)
        print("Ethernet frame -- Destination: {}, Source: {}, Protocol: {}".format(dest, src, proto))
        
        if proto == 8:
            (version, header_length, ttl, proto, src, dest, data) = ipv4_packet(data)
            print(TAB_1 + "IPv4 packet: ")
            print(TAB_2 + "Version: {}, Header Length: {}, TTL: {}, Protocol: {}, Source: {}, Target: {}".format(version, header_length, ttl, proto, src, dest))
            if proto == 1:
                (icmp_type, code, checksum, data) = unpack_ICMP(data)
                print(TAB_2 + "ICMP packet")
                print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print(TAB_2 + "DATA: ")
                print(format_lines(DATA_TAB_3, data))
            elif proto == 6:
                (src_port, dest_port, seq, ack, offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data) = unpack_TCP(data)
                print(TAB_2 + "TCP Segment")
                print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(TAB_2 + "Sequence: {}, Acknowledgment: {}".format(seq, ack))
                print(TAB_2 + "Flags :")
                print(TAB_3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag))
                print(TAB_2 + "DATA: ")
                print(format_lines(DATA_TAB_3, data))
            elif proto == 17:
                (src_port, dest_port, size, data) = unpack_UDP(data)
                print(TAB_2 + "UDP Segment")
                print(TAB_2 + "Source Port: {}, Destination Port: {}, Size: {}".format(src_port, dest_port, size))
                print(TAB_2 + "DATA: ")
                print(format_lines(DATA_TAB_3, data))
            else:
                print("Not yet supported :(")
            	
        
def get_ethernet_frame(data):
    dest, src, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac(dest), get_mac(src), socket.htons(proto), data[14:]

def get_mac(addr):
    byte_array = map('{:02x}'.format, addr)
    return ':'.join(byte_array).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, ip_src, ip_dest = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, get_ipv4(ip_src), get_ipv4(ip_dest), data[header_length:]

def get_ipv4(ip_addr):
    return '.'.join(map(str, ip_addr))

def unpack_ICMP(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

def unpack_TCP(data):
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    urg_flag = (offset_reserved_flags & 32) >> 5 
    ack_flag = (offset_reserved_flags & 16) >> 4 
    psh_flag = (offset_reserved_flags & 8) >> 3 
    rst_flag = (offset_reserved_flags & 4) >> 2 
    syn_flag = (offset_reserved_flags & 2) >> 1 
    fin_flag = offset_reserved_flags & 1
    
    return src_port, dest_port, seq, ack, offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data[offset:]
    
def unpack_UDP(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]
    
def format_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
