import json
from io import BytesIO
from seed import *
from ecc import (
	S256Point
)
from helper import (
	hash256,
	hash160,
	decode_base58, 
	int_to_little,
	little_to_int,
	SIGHASH_ALL, 
	SIGHASH_NONE,
	SIGHASH_SINGLE, 
)
from script import (
	p2pkh_script,
	p2sh_script
)


SEED_PREFIX = b"\x73\x65\x65\x64"
XPRV_PREFIX = b"\x78\x70\x72\x76"

# class UTXO:
# 	"""
# 	UNUSED
# 	class for holding a UTXO info:
# 		-txid (str)
# 		-index (int)
# 		-value (int) in sats
# 	"""
# 	def __init__(self, txid, idx, value):
# 		self.txid = txid
# 		self.idx = idx
# 		self.value = value

# 	def to_json(self):
# 		return {
# 			"tx_id": self.txid,
# 			"idx": self.idx,
# 			"value": self.value
# 		}

class HDPubKey:
	"""
	class for holding a pubkey (S256Point object) and metadata,
	including: 
	-Count (UTXO count)
	-Full Path
	-Label
	Inspiration from Wasabi Wallet.
	"""
	def __init__(self, pubkey, path, label=[], testnet=False):
		self.pubkey = pubkey
		self.path = path
		self.label = label
		self.testnet = testnet
		self.txcount = 0
		self.balance = 0
		self.utxos = []
		self.check_state()

	def get_path(self):
		''' returns path as concatenated bytes'''
		levels = self.path.split("/")
		path_bytes = b""
		for lev in levels:
			i = 0
			if lev[-1] == "'":
				i = SOFT_CAP
				lev = lev[:-1]
			i += int(lev)
			path_bytes += int_to_little(i, 4)

		return path_bytes

	def __repr__(self):
		label =  ", ".join(self.label)
		return f"\"PubKey\": {self.pubkey.sec().hex()},\n\"FullKeyPath\": {self.path},\n\"Label\": {label},\n\"Count\": {self.txcount},\n\"Balance\": {self.balance}"
		
	def to_json(self):
		# utxo_list = []
		# for utxo in self.utxos:
		# 	utxo_list.append(utxo.to_json())
		return {
			"PubKey": self.pubkey.sec().hex(),
			"FullKeyPath": self.path,
			"Label": self.label
		}
	
	@classmethod
	def parse(cls, data):
		sec = bytes(bytearray.fromhex(data["PubKey"]))
		pubkey = S256Point.parse(sec)
		return HDPubKey(pubkey, data["FullKeyPath"], data["Label"])

	def check_state(self):
		"""
		sets txcount and balance. returns balance
		"""	
		addr = self.address()
		tx_hist = get_address(address=addr, testnet=self.testnet).chain_stats
		self.txcount = tx_hist['tx_count']
		self.balance = tx_hist['funded_txo_sum'] - tx_hist['spent_txo_sum']
		return self.balance
		
	def get_utxos(self):
		addr = self.address()
		return get_address_utxo(address=addr, testnet=self.testnet)



	def set_confirmed_utxos(self):
		addr = self.address()
		utxos = get_address_utxo(address=addr, testnet=self.testnet)
		for utxo in utxos:
			if utxo.status.confirmed:
				self.utxos.append(utxo)
		#return len(self.utxos)

	def is_used(self):
		return self.txcount > 0

	def empty(self):
		return self.balance == 0

	def set_label(self, label):
		self.label.append(label)

	def address(self):
		return self.pubkey.address(testnet=self.testnet)

class Wallet:
	DEFAULT_GAP_LIMIT = 10
	DEFAULT_NAME = "Wallet0"
	BASE_PATH = "76'/0'/"
	DUST_LIMIT = 5000
	TX_VERSION = 1
	"""
	A class for storing a single Seed or ExtendedKey in order to manage UTXOs, craft transactions, and more.
	Contains a wallet account (2 layers of depth) and an external (0) and internal (1) account chain, as 
	specified in BIP0032
	"""
	def __init__(self, name=DEFAULT_NAME, passphrase="", testnet=False, data=None, watch_only=False):
		self.name = name
		self.passphrase = passphrase
		self.testnet = testnet
		self.ext_count = 0
		self.int_count = 0
		self.watch_only = watch_only
		
		self.wallet_acct = self.BASE_PATH
		# this standard is defined in BIP0032
		self.ext_chain = 0 # used as 3th layer of derivation path before 4th layer = keys
		self.int_chain = 1 # used as internal chain, for change addr etc.
		self.balance = 0
		self.gap_limit = self.DEFAULT_GAP_LIMIT
		
		self.hdpubkeys = []
		# Load data into wallet, either Seed, Xpub, Xpriv. create necessary keys
		if data is not None:
			#import from seed, xpub, xprv object, or from string xpub or xprv 
			if type(data) == Seed:
				self.seed = data
				self.master_xprv = data.derive_master_priv_key(passphrase=passphrase, testnet=testnet)
				self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
				#self.ext_xpub = self.derive_key((self.wallet_acct + str(self.ext_chain)), priv=True).to_extended_pub_key()
				#self.int_xpub = self.derive_key((self.wallet_acct + str(self.int_chain)), priv=True).to_extended_pub_key()
			elif type(data) == ExtendedPrivateKey:
				self.master_xprv = data
				self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
				#self.ext_xpub = self.derive_key((self.wallet_acct + str(self.ext_chain)), priv=True).to_extended_pub_key()
				#self.int_xpub = self.derive_key((self.wallet_acct + str(self.int_chain)), priv=True).to_extended_pub_key()
				self.seed = None
			elif type(data) == ExtendedPublicKey: # not fully thought-out. Fix Later
				self.master_xpub = data
				self.master_xprv = None
				self.seed = None

			elif type(data) == str:
				if data[:4] == "xprv":
					try:
						self.master_xprv = ExtendedPrivateKey.parse(data)
						self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
						#self.ext_xpub = self.derive_key(self.wallet_acct + str(self.ext_chain), priv=True).to_extended_pub_key()
						#self.int_xpub = self.derive_key((self.wallet_acct + str(self.int_chain)), priv=True).to_extended_pub_key()
						self.seed = None
					
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPRIV key.")
				elif data[:4] == "xpub": # not useful. Think through
					try:
						self.master_xpub = ExtendedPublicKey.parse(data)
						self.master_xprv = None
					except ConfigurationError:
						raise ConfigurationError("Invalid master XPUB key.")
				else:
					raise ConfigurationError("Invalid import format")
		else:
			self.seed = None
			self.master_xprv = None
			self.master_xpub = None

	@classmethod
	def new(cls, passphrase="", strength=128, testnet=False, lang="english"):
		s = Seed.new(strength=128, lang=lang)
		return cls(data=s, passphrase=passphrase, testnet=testnet)


	def mnemonic(self):
		if self.seed:
			return self.seed.mnemonic()
		if self.watch_only:
			raise TypeError("Wallet is watch-only. Seed unknown.")
		if self.seed is None and self.master_xprv is not None:
			raise TypeError("Wallet was created from ExtendedPrivateKey. Seed unknown.")


	@staticmethod
	def fingerprint(xpub):
		return hash160(xpub.to_pub_key().sec())[:4]

	def master_fingerprint(self):
		return self.fingerprint(self.master_xpub)

	def import_seed(self, seed, passphrase):
		self.seed = seed
		self.master_xprv = seed.derive_master_priv_key(passphrase=passphrase, testnet=self.testnet)
		if self.master_xpub:
			newXpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
			if self.master_fingerprint() != self.fingerprint(newXpub):
				raise ConfigurationError("Import Failed.")
		else:
			self.master_xpub = self.derive_key((self.wallet_acct), priv=True).to_extended_pub_key()
		self.watch_only = False
	
#----- WALLET FUNCTIONS -----
#
#----------------------------

	def derive_key(self, path, priv):
		"""
		General function for deriving any key in the account.
		"""
		# if levels.pop() != "m":
		# 	raise ConfigurationError(f"Path must begin with \'m/\'. Begins with {path[0:2]}")
		if priv:
			if self.watch_only:
				raise TypeError("Watch only wallets cannot access Private Keys.")
			levels = path.split("/")
			child = self.master_xprv
			for i in levels:
				try:
					if i[-1] == "'":
						child = child.derive_priv_child( SOFT_CAP + int(i[:-1]) )
					else:
						child = child.derive_priv_child( int(i) )
				except IndexError:
					continue
			return child
		# public keys
		else:
			child = self.master_xpub
			levels = path.split("/")
			for i in levels:
				try:
					if i[-1] == "'": # PubKeys cant make hardened children
						raise TypeError("Hardened Child Keys cannot be derived from Public Parent Key.")
					child = child.derive_pub_child(int(i))
				except IndexError:
					continue
			return child

	def new_pub_key(self, external=True):
		""" 
		generates and returns the next pubkey from the 
		chain
		chain = 0 for external 
		chain = 1 for internal (change addresses)
		"""
		# chain = str(self.ext_chain) if external else str(self.int_chain)
		# path = chain + "/" + str(self.ext_count)
		if external:
			path = f"{self.ext_chain}/{self.ext_count}"
			self.ext_count+=1
		else:
			path = f"{self.int_chain}/{self.int_count}"
			self.int_count+=1
		return self.derive_key(path, priv=False).to_pub_key()

	def new_address(self, external=True):
		""" returns unused address and stores the associated pubkey in self.hdpubkeys """
		return self.new_pub_key(external=external).address(testnet=self.testnet)

	def check_state(self):
		""" calls check_state on each hdPubKey. Sets balance and updates txcount. """
		sats = 0
		for hpk in self.hdpubkeys:
			sats += hpk.check_state() #returns balance of pukey, also updates balance and txcount
		self.balance = sats

	def get_balance(self):
		""" sets and returns wallet balance """
		sats = 0
		for hpk in self.hdpubkeys:
			sats += hpk.check_state()
		self.balance = sats
		return sats

	def get_priv_key(self, i):
		""" gets corresponding privkey from a pubkey using pubkey.path """
		if self.watch_only:
			raise TypeError("Watch only wallet")
		return self.derive_key(self.hdpubkeys[i].path, priv=True).to_priv_key()

	def find_priv_key(self, sec):
		for i, p in enumerate(self.hdpubkeys):
			if p.pubkey.sec() == sec:
				return self.get_priv_key(i)
		return False

	def generate_x_keys(self, x, external=True):
		return {self.new_address(external=external) for _ in range(x)}

	
#----- EXTERNAL FUNCTIONS -----
#
#------------------------------
	
	def to_json(self):
		perm = "watch" if self.watch_only else "total"
		netw = "test" if self.testnet else "main"
		d = {
			"FINGERPRINT": self.fingerprint(self.master_xpub).hex(),
			"ACCT_XPUB": self.master_xpub.__repr__(),
			"ACCT_PATH": self.wallet_acct,
			"NETWORK": netw,
			"PERMISSION": perm,
			"HdPubKeys": [hpk.to_json() for hpk in self.hdpubkeys]
		}
		return d

	@classmethod
	def from_json(self, name, data):
		xpub = ExtendedPublicKey.parse(data["ACCT_XPUB"])
		testnet = data["NETWORK"] == "test"
		w = Wallet(name=name, passphrase="", testnet=testnet, data=xpub, watch_only=True)
		# set watch_only to true in __init__ to avoid generating keys.
		# then set to real value
		w.watch_only = data["PERMISSION"] == "watch"
		w.acct_path = data["ACCT_PATH"]
		ext_count = 0
		int_count = 0
		hdpubkeys = []
		for hpk in data["HdPubKeys"]:
			path = hpk["FullKeyPath"]
			#print(path)
			hdpubkey = HDPubKey.parse(hpk)
			hdpubkeys.append(hdpubkey) 
			#decide if external or internal key
			if w.acct_path in path:#FIX 
				path = path[len(w.acct_path)]
				path = path.replace(w.acct_path, '')
				
				if path[0] == "0":
					#print(path[0])
					ext_count += 1
				elif path[0] == "1":
					#print(path[0])
					int_count += 1
				else:
					#print(path[0])
					pass
		w.hdpubkeys = hdpubkeys
		w.ext_count = ext_count
		w.int_count = int_count
		w.check_state()
		
		return w

	def write_json(self, filename=None):
		if filename is None:
			filename = self.name
		
		json_obj = json.dumps(self.to_json(), indent=4)
		with open(f"{filename}.json", "w+") as fp:
			#verify file matches wallet
			#wallet = self.verify_file(fp)
			#write wallet data
			fp.write(json_obj)
		return True

	@classmethod
	def read_json(cls, filename=DEFAULT_NAME):
		with open(f"{filename}.json", "r") as fp:
			data = json.load(fp) 
		return Wallet.from_json(filename, data)


	@classmethod
	def load(cls, filename, password=None):
		w = Wallet.read_json(filename=filename)
		w.read_secret(filename=filename, password=password)
		
	@classmethod
	def from_mnemonic(cls, mnemonic, lang="english", name=DEFAULT_NAME, passphrase="", testnet=False):
		s = Seed.from_mnemonic(mnemonic, lang=lang)
		return cls(name=name, passphrase=passphrase, testnet=testnet, data=s, watch_only=False)


def address_check(address):
	""" 
	MUST BE MADE BETTER. Very elementary.
	- "1" addresses are of course p2pkh
    - "3" addresses are p2sh but we don't know the redeemScript
    - "bc1" 42-long are p2wpkh
    - "bc1" 62-long are p2wsh 
	"""
	#P2PKH
	if address[0] == "1":
		return True
	#P2SH
	elif address[0] == "3":
		return True
	#P2WPKH or P2WSH
	elif address[:3] == "bc1":
		#P2WPKH
		if len(address) == 42:
			return True
		#P2WSH
		elif len(address) == 62:
			return True
		else:
			return False
	else: 
		return False

if __name__ == "__main__":
	w = Wallet.new()
	print(w.master_xprv)
	print(w.master_xpub)
	print(w.mnemonic())
	print(w.new_address())
	