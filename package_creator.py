import struct
import socket
import random
def pseudo_header(srcip,destip):
    HEADERLENGTH = 20
    PROTOCOLCODE = 6
    zero = 0
    packed_dest_IP = socket.inet_aton(destip)
    packed_src_IP = socket.inet_aton(srcip)
    psödö = struct.pack('!4s4sBBH',packed_src_IP,packed_dest_IP,zero,PROTOCOLCODE,HEADERLENGTH)

    return psödö


def mode_selector(mode):
    scan_type = b''
    if (mode == "-sS" or mode == "SYN"):
        scan_type = b'00000010'
        return scan_type
    elif (mode == "-sA" or mode == "ACK"):
        scan_type = b'00010000'
        return scan_type
    elif (mode == "-sF" or mode == "FIN"):
        scan_type = b'00000001'
        return scan_type
    elif (mode == "-sX" or mode=="XMAS"):
        scan_type = b'00101001'
        return scan_type
    elif(mode == "-sM" or mode=="MAIMON"):
        scan_type =  b'00010001'
        return scan_type
    else:
         
        return scan_type    



def hcreate(sport,dport,mode,srcip,destip):
        psodo_header = pseudo_header(srcip,destip)
        flags = mode_selector(mode)
        ACKMASK = 16
        seq_value = random.randint(0,0xFFFFFFFF)
        try:
            flag_value = int(flags,2)
        except ValueError:
            print("Entered a non-defined mode. Package doesn't created.")
            return
        if flag_value & ACKMASK:
            ack_value = random.randint(0, 0xFFFFFFFF)
        else:
            ack_value = 0
        OFFSET = 5
        reserved = 0000
        bit16_area = (OFFSET << 12) | reserved << 8 | flag_value
        false_header = struct.pack('!HHIIHHHH',sport,dport,seq_value,ack_value,bit16_area,8192,0,0)
        data = false_header + psodo_header
        #return false_header
        true_checksum = checksum(data)
        header = struct.pack('!HHIIHHHH',sport,dport,seq_value,ack_value,bit16_area,8192,true_checksum,0)
        return header


def checksum(data):
    data_len = len(data)
    i = 0;
    total = 0
    while (i < data_len):
        total += struct.unpack("!H",data[i:i+2])[0]
        i+=2
    total = (total >> 16) + (total & 0xFFFF)
    total = (total >> 16) + (total & 0xFFFF)
    total = ~total & 0xFFFF
    return total
def iphdr(source_ip,dest_ip,tcp_header_length):
    IPVERSION = 4
    IHL = 5
    TOS = 0
    TTL = 128
    IPPROTOCOL = 6
    total_length = (IHL * 4) + tcp_header_length
    identification = random.randint(0,0xFFFF)
    version_ihl = (IPVERSION << 4) | IHL
    srcip = socket.inet_aton(source_ip)
    destip = socket.inet_aton(dest_ip)
    FLAGS = 2 #reserved = 0 DF = 1 MF = 0
    FRAGMENT_OFFSET = 0
    flag_n_fragment = (FLAGS << 13) | FRAGMENT_OFFSET
    psodo_iphdr = struct.pack('!BBHHHBBH4s4s',version_ihl,TOS,total_length,identification, flag_n_fragment, TTL, IPPROTOCOL, 0, srcip, destip)
    true_checksum = checksum(psodo_iphdr)
    final_iphdr = struct.pack('!BBHHHBBH4s4s', version_ihl, TOS, total_length, identification, flag_n_fragment, TTL, IPPROTOCOL, true_checksum, srcip, destip)
    return final_iphdr
    
    

def send_packet(sport,dport,mode,srcip,destip):
    try:
        soket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
        soket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        full_packet = iphdr(srcip,destip,20) + hcreate(sport,dport,mode,srcip,destip)
        soket.sendto(full_packet, (destip, 0))

    except PermissionError:
        print("Non-super user detected please use sudo when you use scan modes that required raw socket.")    


