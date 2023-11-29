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
    # print(compressedKey)
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

    b64SessionKey = base64.b64encode(compress(aliceSharedKey).encode('utf-8'))

    # print(compress(aliceSharedKey).encode('utf-8'))

    print("Session Key in Base64 Encoding: \n", b64SessionKey)

    # print(b64SessionKey.len())

    sesKeyTransform = compress(aliceSharedKey)
    sesKeyTransform = sesKeyTransform[2:]
    sesKeyTransform = sesKeyTransform[:-1]
    print("Transformed Key: ", sesKeyTransform)

    return binascii.unhexlify(sesKeyTransform)

def pkcs7padding(data, block_size=16):
  if type(data) != bytearray and type(data) != bytes:
    raise TypeError("Only support bytearray/bytes !")
  pl = block_size - (len(data) % block_size)
  return data + bytearray([pl for i in range(pl)])


def encrypt(pTextMsg, sesKey):

    # AES-256 in CBC Mode using session-key as encryption key

    iv = Random.new().read(AES.block_size)
    
    print(iv)

    byteString = pTextMsg.encode('utf-8')

    paddedString = pkcs7padding(byteString)

    paddedMsg = paddedString.decode('utf-8')

    print("Raw Text: ", pTextMsg)
    print("Padded Text: ", paddedMsg)

    cipher = AES.new(sesKey, AES.MODE_CBC, iv)

    return {
       'cipher_text': base64.b64encode(cipher.encrypt(paddedMsg)),
       'iv': base64.b64encode(iv)
    }

def decrypt(cTextMsg, sesKey):

    pTextMsg = cTextMsg
    return pTextMsg

def hashMsg(string):
    h = hashlib.sha256()
    b = string.encode('utf-8')
    h.update(b)
    hashedMsg = h.digest()
    return hashedMsg

pTextMsg = input("Enter a message: ")

sessionKey = ecdhKeyExchange()

print("Key used for encryption: ", sessionKey)

print(encrypt(pTextMsg, sessionKey))

# hashedPlaintext = hashMsg(pTextMsg)

# print("Hashed Plaintext: ", hashedPlaintext)

# cipherText = encrypt(pTextMsg)

# print(cipherText)

# print(decrypt(cipherText))
