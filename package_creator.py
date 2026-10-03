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

def hcreate(sport,dport,mode):
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

    return false_header















print(len(hcreate(80,85,"SYN")))
print(hcreate(11,19,"ASDAS"))







print(mode_selector("-sS"))
print(mode_selector("SYN"))
print(mode_selector("-sA"))
print(mode_selector("ACK"))
print(mode_selector("-sF"))
print(mode_selector("FIN"))
print(mode_selector("-sX"))
print(mode_selector("XMAS"))
print(mode_selector("-sM"))
print(mode_selector("MAIMON"))
print(mode_selector("ASDASD"))
print(mode_selector(12322313213))







print(pseudo_header("127.0.0.1","127.0.0.1"))