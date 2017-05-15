#For decoded t.wnry file from sample: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA
import sys
import struct
import binascii
import hashlib

def decode_rsa(privkey, data):
	rsa_key = RSA.importKey(privkey)
	cipher = PKCS1_v1_5.new(rsa_key)

	sentinel = Random.new().read(16)
	d = cipher.decrypt(data[::-1],sentinel)
	return d


if __name__ == "__main__":
	data = open(sys.argv[1],'rb').read()
	privkey = open('privkey.der').read()
	hdr = data[:8]
	data = data[8:]
	size = struct.unpack_from('<I', data)[0]
	data = data[4:]
	blob1 = data[:size]
	data = data[size:]
	(id, size) = struct.unpack_from('<IQ', data)
	data = data[12:]
	blob2 = data[:size]
	data = data[size:]
	if data != '':
		print("More data found!")
	key = decode_rsa(privkey, blob1)
	aes = AES.new(key, AES.MODE_CBC, '\x00'*16)
	decoded = aes.decrypt(blob2)
	sha256 = hashlib.sha256(decoded).hexdigest()
	open(sha256, 'wb').write(decoded)
	print("Wrote decoded file to: "+sha256)
