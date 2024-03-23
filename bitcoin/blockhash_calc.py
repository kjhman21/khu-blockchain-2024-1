#!/usr/bin/python3
from hashlib import sha256
from binascii import unhexlify

def hash(msg):
    return sha256(sha256(unhexlify(msg)).digest()).hexdigest()

def hex(n):
    return'{:08x}'.format(n)
    
def to_little(h):
    return ''.join(h[i-2:i] for i in range(len(h), 0, -2))

def to_big(h):
    return ''.join(h[i-2:i] for i in range(len(h), 0, -2))

def calc_target(bits):
    shift = int(bits[0:2], 16)-3
    significand = bits[2:]
    return ''.join('00' for i in range(shift+3,32)) + significand + ''.join('00' for i in range(0, shift))

blockhash = "00000000000000000000d99aa8e95a909e0290e5e48684daae27709ef42e5c04"
version = 700284928
previousblockhash = "00000000000000000001327093c0168c4fda6f65665fc45353e20cb7e36862b4"
merkleroot = "6b5c8ad88878bb5c80b4bed6bb3f41c04ab43385565a230d13ea12c7091a604d"
time = 1710087912
bits = "17038c12"
nonce = 2117288985

message_to_hash = to_little(hex(version)) + to_little(previousblockhash) + to_little(merkleroot) + to_little(hex(time)) + to_little(bits) + to_little(hex(nonce))
print('concatenated:', message_to_hash)
print('hashed:', hash(message_to_hash))
print('hashed_reversed:', to_big(hash(message_to_hash)))
print('blockhash      :', blockhash)
print('target         :', calc_target(bits))

