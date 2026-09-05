import struct 

def main():
    pass

def false_header(srcip,targetip):
    PROTOCOLCODE = 6
    data = b''
    tcp_length = len(data) + 20
    f_header = struct.pack('!HH')