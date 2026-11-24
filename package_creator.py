from queue import Queue
import select
import struct
import socket
import random
import time
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
        tcp_head = hcreate(sport,dport,mode,srcip,destip)
        if tcp_head is None:
            raise SystemExit(f"Invalid scan mode: {mode}")
        full_packet =   iphdr(srcip,destip,len(tcp_head))  + tcp_head
        soket = None

        try:
            soket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
            soket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
            
            
            soket.connect((destip,0))
            soket.send(full_packet)            
            
        except PermissionError:
            print("Non-super user detected please use sudo when you use scan modes that required raw socket.")    
            raise SystemExit(1)
        except  ConnectionError:
            print("A connection issue happened.")
            raise SystemExit(1)
        finally:
            if soket is not None:
                soket.close()
def parse_response(raw_data, expected_sport):
    if len(raw_data) < 20:
        return None
    ihl = (raw_data[0] & 0x0F) * 4
    if len(raw_data) < ihl + 20:
        return None
    tcp_header = raw_data[ihl:ihl + 20]
    tcp_sport, tcp_dport, seq, ack, offset_flags, window, chksum, urg = struct.unpack('!HHIIHHHH', tcp_header)
    if tcp_dport != expected_sport:   
        return None
    flags = offset_flags & 0x3F
    return tcp_sport, {              
        'SYN': bool(flags & 0x02),
        'ACK': bool(flags & 0x10),
        'RST': bool(flags & 0x04),
        'FIN': bool(flags & 0x01),
    }


def collect_responses(recv_sock, destip, sport, expected_ports, timeout=2.0):
    responses = {}                    
    end_time = time.time() + timeout
    while len(responses) < len(expected_ports):
        remaining = end_time - time.time()
        if remaining <= 0:
            break
        ready = select.select([recv_sock], [], [], remaining)
        if not ready[0]:
            break
        raw_data, addr = recv_sock.recvfrom(65535)
        if addr[0] != destip:
            continue
        parsed = parse_response(raw_data, sport)
        if parsed is None:
            continue
        port, flags = parsed
        if port in expected_ports and port not in responses:
            responses[port] = flags
    return responses

def classify_result(mode, response):
    SHORT_TO_LONG = {"-sS": "SYN", "-sA": "ACK", "-sF": "FIN", "-sX": "XMAS", "-sM": "MAIMON"}
    mode = SHORT_TO_LONG.get(mode, mode).upper()

    
    if response is None:
        if mode in ("SYN", "ACK"):
            return "filtered"
        return "open|filtered"        

    rst = response['RST']
    syn_ack = response['SYN'] and response['ACK']

    if mode == "SYN":
        if syn_ack:
            return "open"
        if rst:
            return "closed"

    elif mode == "ACK":
        if rst:
            return "unfiltered"       

    else:                             
        if rst:
            return "closed"

    return "unexpected"

def scan_loop(ports, mode, srcip, destip, sport=40000, timeout=2.0):
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    order = Queue()                  
    try:
        for dport in ports:           
            send_packet(sport, dport, mode, srcip, destip)
            order.put(dport)
        responses = collect_responses(recv_sock, destip, sport, set(ports), timeout)
    finally:
        recv_sock.close()

    results = {}
    while not order.empty():
        port = order.get()
        results[port] = classify_result(mode, responses.get(port))
        print(f"{port}/tcp\t{results[port]}")
    return results


if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        raise SystemExit("Please open it with Super User.")
    for m in ("-sS", "-sA", "-sF", "-sX", "-sM","-sZ"):
        print(f"--- {m} ---")
        scan_loop([22, 80, 443, 8080], m, "127.0.0.1", "127.0.0.1")