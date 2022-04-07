#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__authors__ = "Besseau Léonard, Gamboni Fiona, Michel De la Vallée"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"

import argparse
import binascii
import zlib

from scapy.all import *

from rc4 import RC4


def crypt(message: bytes, key: bytes, iv: bytes) -> (bytes, int):
    cipher = RC4(iv + key, streaming=False)

    # CRC in little indian
    crc = struct.pack('<L', zlib.crc32(message))

    ciphertext = cipher.crypt(message + crc)

    return ciphertext[:-4], struct.unpack('!L', ciphertext[-4:])[0]


parser = argparse.ArgumentParser(prog="Manual WEP encryptor",
                                 usage="manual-encryption.py -i wlp2s0mon -m \"SEND HELP\" -k AA:BB:CC:DD:EE",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")

parser.add_argument("-k", "--Key", required=True,
                    help="The WEP key to use for the encryption")

parser.add_argument("-m", "--Message", required=True,
                    help="The message to encrypt. Limited to 2312 ASCII char (2312 bytes for utf-8). ")

args = parser.parse_args()

key = binascii.unhexlify(args.Key.replace(':', ''))

# Read template capture
arp = rdpcap('arp.cap')[0]

ciphertext, icv = crypt(args.Message.encode('utf-8'), key, arp.iv)
arp.wepdata = ciphertext
arp.icv = icv

wrpcap('encrypted_packet.pcap', arp)

sendp(arp, iface=args.Interface)

print(binascii.hexlify(ciphertext))
