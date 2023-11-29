# Applied Cryptography Final Project Fall 2023
# Authors: Derek Hopkins, Jacob Nevin, Ethan Conner
# This program uses Elliptic Curve Diffie-Hellman for session key distribution (authorization)
# AES-256 in CBC Mode is used for confidentiality
# SHA-256 is used for authentication

# Required Packages:
# tinyec
# pycryptodome

import binascii
from tinyec import registry
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import base64

def compress(pubKey):
    compressedKey = hex(pubKey.x) + hex(pubKey.y % 2)[2:]
    return compressedKey

def ecdhKeyExchange():

    curve = registry.get_curve('secp256r1')
    alicePrivKey = secrets.randbelow(curve.field.n)
    alicePubKey = alicePrivKey * curve.g
    print("Alice public key:", compress(alicePubKey))

    bobPrivKey = secrets.randbelow(curve.field.n)
    bobPubKey = bobPrivKey * curve.g
    print("Bob public key:", compress(bobPubKey))

    print("\nPublic keys can now be exchanged insecurely :)\n")

    aliceSharedKey = alicePrivKey * bobPubKey
    print("Alice shared key:", compress(aliceSharedKey))

    bobSharedKey = bobPrivKey * alicePubKey
    print("Bob shared key:", compress(bobSharedKey))

    print("Equal shared keys:", aliceSharedKey == bobSharedKey)
    
    sesKeyTransform = compress(aliceSharedKey)
   
    sesKeyTransform = sesKeyTransform[2:]
    if(len(sesKeyTransform) % 2 == 1):
        sesKeyTransform = sesKeyTransform[:-1]
    
    print("\nTransformed Key: ", sesKeyTransform, "\n")
    
    return binascii.unhexlify(sesKeyTransform)

def pkcs7padding(data, block_size=16):
  if type(data) != bytearray and type(data) != bytes:
    raise TypeError("Only support bytearray/bytes !")
  pl = block_size - (len(data) % block_size)
  return data + bytearray([pl for i in range(pl)])

# Padding function

def padWithSpaces(data, block_size=16):
    remainder = len(data) % block_size
    padding_needed = block_size - remainder
    return data + padding_needed * ' '


def encrypt(pTextMsg, sesKey):

    # AES-256 in CBC Mode using session-key as encryption key

    iv = Random.new().read(AES.block_size)
    
    paddedBString = padWithSpaces(pTextMsg)

    byteString = paddedBString.encode('utf-8')

    print("Raw Text: ", pTextMsg, "\n")
    print("Padded Text: ", byteString, "\n")

    cipher = AES.new(sesKey, AES.MODE_CBC, iv)

    cText = cipher.encrypt(byteString)

    return {
       'cipher_text': base64.b64encode(cText),
       'iv': base64.b64encode(iv)
    }

def decrypt(encryption_dict, sesKey):

    cText = base64.b64decode(encryption_dict['cipher_text'])
    iv = base64.b64decode(encryption_dict['iv'])

    cipher = AES.new(sesKey, AES.MODE_CBC, iv)

    decryption = cipher.decrypt(cText)

    pTextMsg = decryption.decode('utf-8')

    pTextMsg = pTextMsg.rstrip()

    return pTextMsg
   

def hashMsg(string):
    h = hashlib.sha256()
    b = string.encode('utf-8')
    h.update(b)
    hashedMsg = h.digest()
    return hashedMsg

pTextMsg = input("Enter a message: ")

sessionKey = ecdhKeyExchange()

# print("Key used for encryption: ", sessionKey, "\n")

enc_dict = encrypt(pTextMsg, sessionKey)

cipherText = base64.b64decode(enc_dict['cipher_text'])

print("Cipher Text ==> ", cipherText, "\n")

print("Decrypted Cipher ==> ", decrypt(enc_dict, sessionKey), "\n")

# hashedPlaintext = hashMsg(pTextMsg)

# print("Hashed Plaintext: ", hashedPlaintext)

# cipherText = encrypt(pTextMsg)

# print(cipherText)

# print(decrypt(cipherText))
