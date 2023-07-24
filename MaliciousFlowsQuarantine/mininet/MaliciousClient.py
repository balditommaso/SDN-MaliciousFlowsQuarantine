import socket
import sys
import threading
import time
import os
from six.moves import input

SERVER_IP = sys.argv[1]
SERVER_PORT = 5000

LOCAL_IP = "0.0.0.0"
LOCAL_PORT = 5001

BUFFER_SIZE = 1024

udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
udp_socket.bind((LOCAL_IP, LOCAL_PORT))


def send():
    for i in range(50):
        msg = "attack - " + str(i+1)
        udp_socket.sendto(msg.encode(), (SERVER_IP, SERVER_PORT))
        time.sleep(5)
        
    
def recv():
    count = 0
    while True:
        msg, sender_ip = udp_socket.recvfrom(BUFFER_SIZE)
        if msg.decode() == "q":
            os._exit(1)
        count = count + 1
        print(sender_ip[0] + " >> " + msg.decode() + " (" + str(count) + "/50)")
        


def main():
    send_thread = threading.Thread(target=send)
    recv_thread = threading.Thread(target=recv)
    
    send_thread.start()
    recv_thread.start()
    while True:
        msg = input('type "stop" to terminate the attack:\n')
        if msg == 'stop':
            os._exit(1)
        
if __name__ == '__main__':
    main()