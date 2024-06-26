""" Header
Author: Rojohn Ibana Bañares
"""

""" Resources
https://www.pycryptodome.org/src/cipher/aes
https://www.pycryptodome.org/src/cipher/classic#ctr-mode
https://www.pycryptodome.org/src/public_key/rsa#module-Crypto.PublicKey.RSA
https://www.pycryptodome.org/src/signature/pkcs1_pss#rsa-pss
https://www.pycryptodome.org/src/hash/hmac
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss

class SYMMETRIC_CRYPTOGRAPHY:
	def __init__(self):
		pass

	""" Exercise A.1.a
	Cipher your name using AES 128 CTR mode and store it in a binary file A
	"""

	def cipher_aes128_ctr(self, name: str, nonce_length: int, key: bytes,
					   filename: str):
		data = name if name else input('Enter the data to be ciphered: ')
		data = data.encode('utf-8')
		print('Encrypting the data')
		cipher = AES.new(key, AES.MODE_CTR,
				   nonce=get_random_bytes(nonce_length))
		with open(filename, 'wb') as file:
			file.write(cipher.nonce)
			file.write(cipher.encrypt(data))
		print('The data has been encrypted')

	""" Exercise A.1.b
	Load the file A and decipher the data using AES 128 CTR mode
	"""

	def decipher_aes128_ctr(self, name: str, nonce_length: int, key: bytes,
						 filename: str):
		with open(filename, 'rb') as file:
			nonce = file.read(nonce_length)
			cipher_text = file.read()
			print('Decrypting the data')
			cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
			result = cipher.decrypt(cipher_text).decode('utf-8')
			print(f'The decrypted text is: {result}')

class ASYMMETRIC_CRYPTOGRAPHY:
	def __init__ (self):
		self._public_key = None
		self._private_key = None

	""" Exercise A.2.a
	Sign your name using RSA and store it in a binary file B
	"""
	def generate_rsa_key(self, password: str):
		print('Generating RSA key')
		rsa_key = RSA.generate(3072)
		self._private_key = rsa_key.export_key(passphrase=password,
						pkcs=8,
						protection='PBKDF2WithHMAC-SHA1AndAES256-CBC',
						prot_params={'iteration_count': 131072})
		self._public_key = rsa_key.publickey().export_key()

	def signature_rsa(self, name: str, filename2: str, password: bytes):
		password = password if password else input('Enter the password: ')
		if password == '':
			password = 'SamsungUmaCybersecurity2024'
		password = password.encode('utf-8')
		self.generate_rsa_key(password)
		data = name if name else input('Enter the data to be signed: ')
		data = data.encode('utf-8')
		print('Signing the data')
		rsa_key = RSA.import_key(self._private_key, passphrase=password)
		hash = SHA256.new(data)
		signature = pss.new(rsa_key).sign(hash)
		with open(filename2, 'wb') as file:
			file.write(signature)
		print('The data has been signed')

	""" Exercise A.2.b
	Apply HMAC to your name using SHA256 and store it in a binary file C
	"""

	def hmac_sha256(self, name: str, key: bytes, filename3: str):
		data = name if name else input('Enter the data to be hashed: ')
		data = data.encode('utf-8')
		print('Hashing the data')
		hash = HMAC.new(key, digestmod=SHA256)
		hash.update(data)
		result = hash.digest()
		with open(filename3, 'wb') as file:
			file.write(result)
		print('The data has been hashed')

	""" Exercise A.2.c
	Load the file B and verify the signature is the same
	"""

	def verify_signature_rsa(self, name: str, filename2: str):
		with open(filename2, 'rb') as file:
			signature = file.read()
			data = name if name else input('Enter the data to be verified: ')
			data = data.encode('utf-8')
			print('Verifying the signature')
			key = RSA.import_key(self._public_key)
			hash = SHA256.new(data)
			try:
				pss.new(key).verify(hash, signature)
				print('The signature is authentic')
			except ValueError:
				print('The signature is not authentic')

	""" Exercise A.2.d
	Load the file C and verify the hash is the same.
	"""

	def verify_hmac_sha256(self, name: str, key: bytes, filename3: str):
		with open(filename3, 'rb') as file:
			data = name if name else input('Enter the data to be verified: ')
			data = data.encode('utf-8')
			print('Verifying the hash')
			hash = HMAC.new(key, digestmod=SHA256)
			hash.update(data)
			try:
				mac = file.read()
				hash.verify(mac)
				print(f'The data is valid')
			except ValueError:
				print(f'The data is invalid')

def main():
	name = 'Rojohn Ibana Bañares' # Set to None to input data
	password = 'SamsungUmaCybersecurity2024' # Set to None to input data
	aes_key = get_random_bytes(16)
	hmac_key = get_random_bytes(32)
	nonce_length = 8
	filename = 'A'
	filename2 = 'B'
	filename3 = 'C'
	part1 = SYMMETRIC_CRYPTOGRAPHY()
	part2 = ASYMMETRIC_CRYPTOGRAPHY()
	part1.cipher_aes128_ctr(name, nonce_length, aes_key, filename)
	part1.decipher_aes128_ctr(name, nonce_length, aes_key, filename)
	part2.signature_rsa(name, filename2,  password)
	part2.hmac_sha256(name, hmac_key, filename3)
	part2.verify_signature_rsa(name, filename2)
	part2.verify_hmac_sha256(name, hmac_key, filename3)

if __name__ == '__main__':
	main()
