from tinyec import registry
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import base64

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def ecdhKeyExchange():

    curve = registry.get_curve('secp256r1')
    alicePrivKey = secrets.randbelow(curve.field.n)
    alicePubKey = alicePrivKey * curve.g
    print("Alice public key:", compress(alicePubKey))

    bobPrivKey = secrets.randbelow(curve.field.n)
    bobPubKey = bobPrivKey * curve.g
    print("Bob public key:", compress(bobPubKey))

    print("\nNow exchange the public keys (e.g. through Internet)\n")

    aliceSharedKey = alicePrivKey * bobPubKey
    print("Alice shared key:", compress(aliceSharedKey))

    bobSharedKey = bobPrivKey * alicePubKey
    print("Bob shared key:", compress(bobSharedKey))

    print("Equal shared keys:", aliceSharedKey == bobSharedKey)

    b64SessionKey = base64.b64encode(compress(aliceSharedKey).encode('utf-8'))

    print("Session Key in Base64 Encoding: \n", b64SessionKey)

    return b64SessionKey

def pkcs7padding(data, block_size=16):
  if type(data) != bytearray and type(data) != bytes:
    raise TypeError("Only support bytearray/bytes !")
  pl = block_size - (len(data) % block_size)
  return data + bytearray([pl for i in range(pl)])


def encrypt(pTextMsg, key):

    # AES-256 in CBC Mode using session-key as encryption key

    byteString = pTextMsg.encode('utf-8')

    paddedString = pkcs7padding(byteString)

    paddedMsg = paddedString.decode('utf-8')

    print("Raw Text: ", pTextMsg)
    print("Padded Text: ", paddedMsg)

    cTextMsg = pTextMsg
    return cTextMsg

def decrypt(cTextMsg, key):

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

encrypt(pTextMsg, sessionKey)

# hashedPlaintext = hashMsg(pTextMsg)

# print("Hashed Plaintext: ", hashedPlaintext)

# cipherText = encrypt(pTextMsg)

# print(cipherText)

# print(decrypt(cipherText))