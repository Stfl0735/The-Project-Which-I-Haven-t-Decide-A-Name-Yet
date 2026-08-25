import socket

toutList = [300,100,50,20,10,5]


def tcp_connect_scanner(hostaddr="",ports=[0],tout_val=3):
    
        
        for port in ports:
            mysock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            mysock.settimeout(toutList[tout_val])
            try:
                mysock.connect((hostaddr,port))
                print(f"Port {port} is open.") 
            except socket.timeout:
                 print(f"Port {port} is filtered.")
            except ConnectionRefusedError:
                 print(f"Port {port} is closed.")
            finally:
                 mysock.close()

                  
def list_creator(minval=0,maxval=63565):
    mylist = [x for x in range(minval,maxval)]
    return mylist
          
            

def main():
    tcp_connect_scanner("192.168.56.101",[21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38],4)             
     
main()
