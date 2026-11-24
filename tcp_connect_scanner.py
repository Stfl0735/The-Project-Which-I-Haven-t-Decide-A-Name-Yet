import socket

TOUT_MS = [300,100,50,20,10,5]


def tcp_connect_scanner(hostaddr="",ports=[0],tout_val=3):
        timeout = TOUT_MS[tout_val]/1000
        results = {}
        for port in ports:
            mysock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            mysock.settimeout(timeout)
            try:
                mysock.connect((hostaddr,port))
                results[port] = "open" 
            except TimeoutError:
                 results[port] = "filtered"
            except ConnectionRefusedError:
                 results[port] = "closed"
            except OSError as o:
                 results[port] = f"error ({e.strerror})"
            finally:     
                 mysock.close()
        print(f"{port}:{results[port]}")
        return results          
def list_creator(minval=0,maxval=65535):
    mylist = [x for x in range(minval,maxval + 1)]
    return mylist
          
            

def main():
    tcp_connect_scanner("127.0.0.1",list_creator(20,38),4)             
     
if __name__ == "__main__":
    main()
