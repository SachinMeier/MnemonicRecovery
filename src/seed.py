
import random
from secrets import token_bytes
import os
from hashlib import (
	sha256, 
	sha512, 
	pbkdf2_hmac
)
import hmac
from ecc import (
	S256Point,
	PrivateKey,
	N, 
	G, 
	P
)
import unicodedata
from helper import (
	encode_base58,
	a2b_base58,
	hash256,
	hash160
)

"""
Disclaimer: 

Credit: Parts of the Seed class are derived from Trezor's reference 
implementation, linked from bip 0039. Link: https://github.com/trezor/python-mnemonic/blob/master/mnemonic/mnemonic.py
Functions taken from here will be noted with 'taken from Trezor Ref-Implementation'

mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
"""
PRIV_MAIN = b"\x04\x88\xad\xe4"
PRIV_TEST = b"\x04\x35\x83\x94"
PUB_MAIN = b"\x04\x88\xb2\x1e"
PUB_TEST = b"\x04\x35\x87\xcf"

STRENGTHS = [128, 160, 192, 224, 256]
CS_STRENGTHS = [132, 165, 198, 233, 264]
SOFT_CAP = 2**31 #2**31 = range of unhardened keys
HARD_CAP = SOFT_CAP<<1 #2**32 = range of hardened keys
PBKDF2_ROUNDS = 2048
RADIX = 2048 # length of wordlist
# this message adapted from https://github.com/richardkiss/pycoin/blob/master/pycoin/key/bip32.py
INVALID_KEY_MSG = """
You have found an invalid key!! Please save this XPub, XPriv, and the i (the number of the child).
This data will help Bitcoin devs. If there are any coins in this wallet, move them before sharing
key info. 
e-mail "Richard Kiss" <him@richardkiss.com> or "Matt Bogosian" <mtb19@columbia.edu> for
instructions on how best to donate it without losing your bitcoins.

To continue and generate a valid key, simply increment i (the child_num). 

WARNING: DO NOT SEND ANY WALLET INFORMATION UNLESS YOU WANT TO LOSE ALL
THE BITCOINS IT CONTAINS.
""".strip()

class ConfigurationError(Exception):
	pass

def binary_search(nList, target, low=0, high=None):
	if high is None:
		 high = len(nList)
	if low > high:
		return -1
	pos = (low + high) // 2
	if nList[pos] > target:
		return binary_search(nList, target, low, pos-1)
	elif nList[pos] < target:
		return binary_search(nList, target, pos+1, high)
	else:
		return pos

def getRandom(length):
	return token_bytes(length//8)
	#return sha256(os.urandom(length)).digest()[:length//8]

# taken from Trezor Ref-Implementation
def get_directory():
    return os.path.join(os.path.dirname(__file__), "wordlist")

def main():
	s1 = Seed()
	s1.generate(128)
	xprv = s1.derive_master_priv_key()
	xpub = xprv.to_extended_pub_key()
	print("Seed:", s1)
	print("Mnemonic:", s1.mnemonic())
	print("xprv:", xprv)
	print("xpub:", xpub)

class Seed:
	""" 
	A class for storing bits of entropy of len [128, 160, 192, 224, 256] for processing
	into BIP32 Master Extended Private Keys and BIP39 Mnemonic Phrases. 
	Language defaults to English and Length defaults to 128 bits (12 words)
	"""
	def __init__(self, bits="", strength=0, lang="english"):
		if lang != "english":
			raise ConfigurationError(f"Language {lang} not implemented. Use English, Spanish, French, Japanese, Chinese, Korean, or Italian.")
		self.bits = bits
		self.check_sum(self.bits)
		self.strength = strength if bits == "" else (len(bits) - len(bits)//33)
		#taken from Trezor Ref-Implementation
		with open(f"{get_directory()}/{lang}.txt", "r", encoding="utf-8") as f:
			self.wordlist = [w.strip() for w in f.readlines()]
		if len(self.wordlist) != RADIX:
			error = f"Wordlist should contain {RADIX} words, but it contains {len(self.wordlist)} words."
			raise ConfigurationError(error)

	def __repr__(self):
		if self.bits == "":
			return "Seed(null)"
		else:
			return f"Seed(\"{self.seed().hex()}\")"

	def display(self, passwd=None):
		if self.bits == "":
			print("Seed(null)")
		else:
			print("Entropy Bits: " + self.bits)
			print("Seed: " + self.seed(passwd))
			print("Mnemonic: " + self.mnemonic())
			xprv = self.derive_master_priv_key()
			print("xprv: " + xprv)
			print("xpub: " + xprv.to_extended_pub_key())

	def set_entropy(self, entropy):
		""" takes entropy as hex string and converts to bits. """
		if self.bits != "":
			raise ConfigurationError("Bits cannot be altered once set. Create a new Seed object.")
		#if len(entropy) in [s//4 for s in STRENGTHS]:
		strength = len(entropy)*4
		checksumlen = strength//32
		entropy = bytes(bytearray.fromhex(entropy))
		chash = sha256(entropy).hexdigest()
		checksum = bin(int(chash, 16))[2:].zfill(256)[:checksumlen]
		entropy = bin(int.from_bytes(entropy, 'big'))[2:].zfill(strength) + checksum
		# elif len(entropy) in [s//4 for s in CS_STRENGTHS]:
		# 	pass
		# else:
		# 	raise ConfigurationError("Invalid Entropy Length")
		self.bits = entropy
		self.strength = strength

	def generate(self, strength=128):
		""" 
		Generates random entropy using the getRandom function. Sets self.bits to entropy
		and self.strength to strength. 		
		"""
		if self.strength != 0 and self.strength != strength:
				raise ConfigurationError(f"Strength already set to {self.strength}. Cannot be changed to {strength}.")
		if strength not in STRENGTHS:
				raise ConfigurationError(f"strength must be in {STRENGTHS}, not {strength}")
		checksumlen = strength//32
		rand = getRandom(strength)
		chash = sha256(rand).digest()
		checksum = bin(int.from_bytes(chash, 'big'))[2:].zfill(256)[:checksumlen]
		bits = bin(int.from_bytes(rand, 'big'))[2:].zfill(strength) + checksum
		self.bits = bits
		self.strength = strength

	@classmethod
	def new(cls, strength=128, lang="english"):
		"""
		classmethod for generating new Seed object with entropy from getRandom
		"""
		if strength not in STRENGTHS:
			raise ConfigurationError(f"Strength must be in {STRENGTHS}, not {strength}")
		checksumlen = strength//32
		rand = getRandom(strength)
		chash = sha256(rand).hexdigest()
		checksum = bin(int(chash, 16))[2:].zfill(256)[:checksumlen]
		bits = bin(int.from_bytes(rand, 'big'))[2:].zfill(strength) + checksum
		return cls(bits=bits, strength=strength, lang=lang)

	def mnemonic(self):
		"""
		returns list of seed phrase words of length [12, 15, 18, 21, 24] from entropy.
		If no entropy exists, Seed::generate is called to create new entropy.
		"""
		if self.bits == "":
			self.generate(128)
		mnemonic = []
		for i in range(0, len(self.bits), 11):
			idx = int(self.bits[i : i+11], 2)
			mnemonic.append((self.wordlist[idx]))
		return mnemonic
	
	@classmethod
	def from_mnemonic(cls, mnemonic, lang="english"):
		with open("%s/%s.txt" % (get_directory(), lang), "r", encoding="utf-8") as f:
			wordlist = [w.strip() for w in f.readlines()]
		if len(wordlist) != RADIX:
			error = f"Wordlist should contain {RADIX} words, but it contains {len(wordlist)} words."
			raise ConfigurationError(error)
		try:
			if lang == "english": # binary search only possible for english 
				bits = map(lambda m: bin(binary_search(wordlist, m))[2:].zfill(11), mnemonic)
				bits = "".join(bits)
			else:
				bits =  map(lambda m: bin(wordlist.index(m))[2:].zfill(11), mnemonic)
				bits = "".join(bits)
		except ValueError:
			raise ConfigurationError("Invalid Mnemonic Phrase.")
		strength = len(mnemonic)*11
		strength -= (strength//33) #remove chekcsum from strength
		return cls(bits=bits, strength=strength, lang=lang)

	@classmethod 
	def from_bits(cls, entropy, lang="english"):
		"""
		a Seed can be parsed from a from binary string of bits
		binary str -> entropy bits
		"""
		if type(entropy) == str:
			return cls(entropy, lang)
		else:
			raise ValueError("Seed::parse requires entropy bits as binary string")

	@classmethod
	def from_bytes(cls, data, lang="english"):
		"""
		Load a seed from bytes (including checksum)
		bytes -> bits
		"""
		checksumlen = len(data)//4
		chash = sha256(data).digest()
		checksum = bin(int.from_bytes(chash, 'big'))[2:].zfill(256)[:checksumlen]
		#print("seedlen2:",len(data))
		strength = len(data)*8
		#print("strength:",strength)
		bits = bin(int.from_bytes(data, 'big'))[2:].zfill(strength)
		bits += checksum
		return cls(bits, strength=strength, lang=lang)

	@classmethod
	def check_sum(cls, bits):
		"""
		Checks checksum of entropy.
		"""
		l = len(bits)
		strength = l - (l//33)
		entropy = bits[:strength]
		checksum = bits[strength:]
		chash = sha256(int(entropy,2).to_bytes(l//8, 'big')).hexdigest()
		return checksum == bin(int(chash, 16))[2:].zfill(256)[:l//33]
		
	# taken from Trezor Ref-Implementation
	def seed(self, passphrase=""):
		"""
		returns bytes of seed, which is used to derive master XPriv key (Seed::derive_master_priv_key)
		"""
		m = " ".join(self.mnemonic())
		unicodedata.normalize("NFKD", m)
		p = unicodedata.normalize("NFKD", passphrase)
		p = "mnemonic" + p
		m = m.encode("utf-8")
		p = p.encode("utf-8")
		stretched = pbkdf2_hmac("sha512", m, p, PBKDF2_ROUNDS)
		return stretched[:64]

	def derive_master_priv_key(self, passphrase="", testnet=False):
		"""
		returns XPRIV key as defined in BIP39 from seed. 
		"""
		if self.bits == "":
			self.generate(strength=128)
		ii = hmac.new(b"Bitcoin seed", self.seed(passphrase), digestmod=sha512).digest()
		#testnet prefix
		xprv = PRIV_MAIN
		if testnet:
			xprv = PRIV_TEST
		# 1 for depth, 4 for empty parent fingerprint, 4 for empty child number
		xprv += b"\x00" * 9
		# add chain code 32 bytes
		xprv += ii[32:]  
		# add master key 33 bytes
		xprv += b"\x00" + ii[:32]  
		# add checksum
		checksum = hash256(xprv)[:4] 
		xprv += checksum
		#return encode_base58_checksum(xprv)
		#print(len(xprv))
		return ExtendedPrivateKey(xprv)
		
	@classmethod
	def to_master_priv_key(cls, seed=None, strength=128, passphrase="", lang="english", testnet=False):
		"""
		classmethod for generating new seed and returning master xprv key. 
		Strength defaults to 128, and testnet defaults to False.
		Seed can also optionally be set to bytes to load master xprv from seed.
		"""
		if seed is None:
			seed = Seed.new(strength=strength, lang=lang).seed(passphrase)
		ii = hmac.new(b"Bitcoin seed", seed, digestmod=sha512).digest()
		#testnet prefix
		xprv = PRIV_MAIN
		if testnet:
			xprv = PRIV_TEST
		# 1 for depth, 4 for empty parent fingerprint, 4 for empty child number
		xprv += b"\x00" * 9
		# add chain code 32 bytes
		xprv += ii[32:]  
		# add master key 33 bytes
		xprv += b"\x00" + ii[:32]
		# add checksum
		checksum = hash256(xprv)[:4] 
		xprv += checksum
		return ExtendedPrivateKey(xprv)

class ExtendedPrivateKey:
	"""
	Class for BIP32 Extended Private Keys (XPRVs). Capable of deriving hardened and normal children
	as well as Extended Public Keys (XPUBs). Parse XPRVs either from base58-encoded string or directly from 
	a seed using parse or from_seed respectively.
	Both XPRVs and XPUBS can be used in a Wallet object.
	"""
	def __init__(self, xprv):
		self.testnet = (xprv[:4] == PRIV_TEST)
		self.depth = xprv[4:5]
		self.parent = xprv[5:9]
		self.child_num = xprv[9:13]
		self.chaincode = xprv[13:45]
		self.key = xprv[45:-4]
		self.checksum = xprv[-4:]
		
		if not self.check_sum():
			raise ConfigurationError("Invalid Checksum for ExtendedPrivKey")

	def __repr__(self):
		if self.testnet:
			xpriv = PRIV_TEST
		else:
			xpriv = PRIV_MAIN
		xpriv += self.depth + self.parent + self.child_num + self.chaincode + self.key + self.checksum
		return encode_base58(xpriv)

	def to_priv_key(self):
		return PrivateKey(int.from_bytes(self.key, 'big'))

	def to_pub_key(self):
		return self.to_priv_key().point

	def to_extended_pub_key(self):
		xpub = PUB_TEST if self.testnet else PUB_MAIN
		xpub += self.depth
		# print(len(self.depth))
		xpub += self.parent
		# print(len(self.parent))
		xpub += self.child_num
		# print(len(self.child_num))
		xpub += self.chaincode
		# print(len(self.chaincode))
		xpub += self.to_pub_key().sec()
		# print(len(self.to_pub_key().sec()))
		checksum = hash256(xpub)[:4]
		xpub += checksum
		# print(len(xpub))
		return ExtendedPublicKey(xpub)

	def derive_priv_child(self, i):
		if i >= HARD_CAP:
			return ValueError("Chosen i is not in range [0, 2**32-1]")
		if i >= SOFT_CAP: # hardened
			ii = hmac.new(self.chaincode, self.key + i.to_bytes(4, 'big'), digestmod=sha512).digest()
		else: #unhardened
			ii = hmac.new(self.chaincode, self.to_priv_key().point.sec() + i.to_bytes(4, 'big'), digestmod=sha512).digest()

		key = (int.from_bytes(ii[:32], 'big') + int.from_bytes(self.key, 'big'))%N # from ecc.py
		fingerprint = hash160(self.to_pub_key().sec())[:4]
		child_xprv = PRIV_MAIN
		if self.testnet:
			child_xprv = PRIV_TEST
		child_xprv += (self.depth[0] + 1).to_bytes(1, 'big')
		child_xprv += fingerprint
		child_xprv += i.to_bytes(4, 'big')
		# add chaincode 
		child_xprv += ii[32:]
		# add key
		child_xprv += b"\x00" + key.to_bytes(32 , 'big')
		checksum = hash256(child_xprv)[:4] 
		child_xprv += checksum
		return self.__class__(child_xprv)

	def derive_pub_child(self, i):
		if i >= HARD_CAP:
			return ValueError("Chosen i is not in range [0, 2**32-1]")
		return self.derive_priv_child(i).to_extended_pub_key()

	def check_sum(self):
		if self.testnet:
			xprv = PRIV_TEST
		else:
			xprv = PRIV_MAIN
		xprv += self.depth + self.parent + self.child_num + self.chaincode + self.key
		if self.checksum != hash256(xprv)[:4]:
			return False
		return True

	def to_bytes(self):
		xprv = PRIV_MAIN if self.testnet else PRIV_TEST
		xprv += self.depth + self.parent + self.child_num
		xprv += self.chaincode + self.key + self.checksum
		return xprv

	@classmethod
	def from_seed(cls, seed, passphrase=""):
		return Seed.to_master_priv_key(seed=seed, passphrase=passphrase)

	@classmethod
	def parse(cls, xprv): # from xprv string
		return cls(a2b_base58(xprv))

class ExtendedPublicKey:
	"""
	Class for BIP32 Extended Public Keys (XPRVs). Capable of deriving unhardened  children.
	Parse XPUBs either from base58-encoded string or directly from 
	a seed using parse or from_seed respectively. 
	Load an XPUB into a Wallet object to create a watch-only wallet.
	"""
	def __init__(self, xpub):
		self.testnet = (xpub[:4] == PUB_TEST)
		self.depth = xpub[4:5]
		# print(type(self.depth))
		self.parent = xpub[5:9]
		# print(type(self.parent))
		self.child_num = xpub[9:13]
		# print(type(self.child_num))
		self.chaincode = xpub[13:45]
		# print(type(self.chaincode))
		self.key = xpub[45:-4]
		# print(type(self.key))
		self.checksum = xpub[-4:]
		# print(type(self.checksum))
		if not self.check_sum():
			raise ConfigurationError("Invalid Checksum for ExtendedPrivKey")
		try:
			point = S256Point.parse(self.key)
		except ValueError:
			raise ConfigurationError("Point is not on the curve, invalid key.")
			
	def __repr__(self):
		if self.testnet:
			xpub = PUB_TEST
		else:
			xpub = PUB_MAIN
		xpub += self.depth + self.parent + self.child_num + self.chaincode + self.key + self.checksum
		return encode_base58(xpub)

	def check_sum(self):
		if self.testnet:
			xpub = PUB_TEST
		else:
			xpub = PUB_MAIN
		xpub += self.depth + self.parent + self.child_num + self.chaincode + self.key
		if self.checksum != hash256(xpub)[:4]:
			return False
		return True
		
	def to_pub_key(self):
		return S256Point.parse(self.key)

	def derive_pub_child(self, i):
		if i >= HARD_CAP:
			return ValueError("Chosen i is not in range [0, 2**32-1]")
		# Not quite sure if this is true
		# if int.from_bytes(self.child_num, 'big') >= SOFT_CAP:
		# 	raise TypeError("Hardened Public Keys cannot derive child keys. Use Extended Private key.")
		if i >= SOFT_CAP:
			raise TypeError("Hardened Keys cannot be be derived from Extended Pub Keys. Use Extended Private key.")
		else:
			ii = hmac.new(self.chaincode, self.key + i.to_bytes(4, 'big'), digestmod=sha512).digest()
		fingerprint = hash160(self.key)[:4]
		# edge case: invalid keys
		key_num = int.from_bytes(ii[:32], 'big')
		point = key_num * G
		if key_num >= N or point.x is None:
			raise ValueError(INVALID_KEY_MSG)
		child_key = point + S256Point.parse(self.key)
		child_chaincode = ii[32:]
		#assemble new xpub
		child_xpub = PUB_MAIN
		if self.testnet:
			child_xpub = PUB_TEST
		child_xpub += (self.depth[0] + 1).to_bytes(1, 'big')
		child_xpub += fingerprint
		child_xpub += i.to_bytes(4, 'big')
		child_xpub += child_chaincode
		child_xpub += child_key.sec()
		checksum = hash256(child_xpub)[:4]
		child_xpub += checksum
		return self.__class__(child_xpub)

	@classmethod
	def parse(cls, xpub): # from xpub string
		return cls(a2b_base58(xpub))

	@classmethod
	def from_seed(cls, seed):
		return ExtendedPrivateKey.from_seed(seed=seed).to_extended_pub_key()



if __name__ == "__main__":
	main()
	#xpub = ExtendedPublicKey.parse()