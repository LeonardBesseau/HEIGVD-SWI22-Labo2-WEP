#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt message as wep given the WEP key"""

__authors__ = "Besseau Léonard, Gamboni Fiona, Michel De la Vallée"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"

import argparse
import binascii

from scapy.all import *
from scapy.layers.dot11 import RadioTap

from rc4 import RC4


def crypt(message: bytes, key: bytes, iv: bytes) -> (bytes, int):
    """
    Encrypt a message and return the ciphertext + the encrypted crc for the plaintext
    """
    cipher = RC4(iv + key, streaming=False)

    # Convert CRC to bytes
    # We need to fix the crc to 32 bits
    crc = struct.pack('I', binascii.crc32(message) & 0xffffffff)

    ciphertext = cipher.crypt(message + crc)

    return ciphertext[:-4], struct.unpack('!L', ciphertext[-4:])[0]


parser = argparse.ArgumentParser(prog="Manual WEP encryptor",
                                 usage="manual-encryption.py -i wlp2s0mon -m \"SEND HELP\" -k AA:BB:CC:DD:EE -v "
                                       "AA:AA:AA",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")

parser.add_argument("-k", "--Key", required=True,
                    help="The WEP key to use for the encryption. Must be 5 bytes in hexadecimal separated by : ("
                         "AA:AA:AA:AA:AA)")

parser.add_argument("-v", "--Iv", required=False,
                    help="The IV to use. Must be 3 bytes in hexadecimal separated by : (AA:AA:AA)", default=None)

parser.add_argument("-m", "--Message", required=True,
                    help="The message to encrypt.")

args = parser.parse_args()

key = binascii.unhexlify(args.Key.replace(':', ''))

# Read template capture
arp = rdpcap('arp.cap')[0]

# Crypt Message and generate ICV
# Padding is for Logical-Link-Control dummy data
ciphertext, icv = crypt(b'\x00' * 6 + args.Message.encode('ascii'), key,
                        arp.iv if args.Iv is None else binascii.unhexlify(args.Iv.replace(':', '')))

# Update packet with new data
if args.Iv is not None:
    arp.iv = binascii.unhexlify(args.Iv.replace(':', ''))
arp.wepdata = ciphertext
arp.icv = icv

# We have to set the length to None to force Scapy to recompute it
arp[RadioTap].len = None

# Write packet
wrpcap('encrypted_packet.pcap', arp)
