import socket
import sys

LOCAL_IP = "0.0.0.0"

LOCAL_PORT = 5000

CLIENT_PORT = 5001

BUFFER_SIZE = 1024

def main():
    udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp_socket.bind((LOCAL_IP, LOCAL_PORT))
    print("UDP echo server up and listening -> " + LOCAL_IP + ":" + str(LOCAL_PORT))
    
    # listening for incoming datagrams
    while (True):
        # print the received message
        message, client_ip = udp_socket.recvfrom(BUFFER_SIZE)
        print(client_ip[0] + " >> " + message)
        
        # send echo replay
        udp_socket.sendto(message, (client_ip[0], CLIENT_PORT))

if __name__ == '__main__':
    main()