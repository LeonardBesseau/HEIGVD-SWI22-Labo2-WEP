#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Split a message in three fragments and manually encrypt them as wep given the WEP key"""

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
    # We need to fix the crc to 4 bytes
    crc = struct.pack('I', binascii.crc32(message) & 0xffffffff)

    ciphertext = cipher.crypt(message + crc)

    return ciphertext[:-4], struct.unpack('!L', ciphertext[-4:])[0]


parser = argparse.ArgumentParser(prog="Manual WEP encryptor",
                                 usage="fragmentation.py -i wlp2s0mon -m \"SEND HELP\" -k AA:BB:CC:DD:EE -v "
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

arp = rdpcap('arp.cap')[0]

output = PcapWriter("fragment.pcap", append=True, sync=True)

fragments = []
# Padding for logical link control
plaintext = b'\x00' * 6 + args.Message.encode('ascii')

fragmentSize = math.ceil(len(plaintext) / 3)

# transform message into 3 fragments
for i in range(0, 3):
    frag = plaintext[i * fragmentSize: (i + 1) * fragmentSize]
    frag += b'\0' * (fragmentSize - len(frag))
    fragments.append(frag)

for i, fragment in enumerate(fragments):
    # Crypt Message and generate ICV
    ciphertext, icv = crypt(fragment, key,
                            arp.iv if args.Iv is None else binascii.unhexlify(args.Iv.replace(':', '')))

    # Update packet with new data
    if args.Iv is not None:
        arp.iv = binascii.unhexlify(args.Iv.replace(':', ''))
    arp.wepdata = ciphertext
    arp.icv = icv

    # We have to set the length to None to force Scapy to recompute it
    arp[RadioTap].len = None

    # we set the FCfield depending on whether it's the last fragment or not
    arp.FCfield.MF = True if i != len(fragments) - 1 else False

    # update fragment count
    arp.SC = i

    output.write(arp)
