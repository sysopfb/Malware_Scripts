import sys
import binascii
import pefile
import hashlib
from Crypto.Cipher import AES

def derive_key(n_rounds,input_bf):
	intermediate = input_bf
	for i in range(0, n_rounds):
		sha = hashlib.sha256()
		sha.update(intermediate)
		current = sha.digest()
		intermediate += current
	return current

#expects a str of binary data open().read()
def dyre_decrypt(data):
	key = derive_key(128, data[:32])
	iv = derive_key(128,data[16:48])[:16]
	aes = AES.new(key, AES.MODE_CBC, iv)
	mod = len(data[48:]) % 16
	if mod != 0:
		data += '0' * (16 - mod)
	return aes.decrypt(data[48:])[:-(16-mod)]

if __name__ == "__main__":
	data = open(sys.argv[1],'rb').read()


	decoded = dyre_decrypt(data)

	open(sys.argv[1]+'.decr','wb').write(decoded)
