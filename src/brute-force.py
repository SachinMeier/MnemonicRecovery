import seed
from bitarray import bitarray
from hashlib import sha256
import os
from wallet import address_check, Wallet

def get_directory():
    return os.path.join(os.path.dirname(__file__), "wordlist")

def binary_search(nList, target, low=0, high=None):
	if target == "":
		return 0
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

def get_lang():
	langs = {
		1: "english",
		2: "chinese_simplified",
		3: "chinese_traditional",
		4: "french",
		5: "italian",
		6: "japanese",
		7: "korean",
		8: "spanish"
	}
	print("Select a Language: ")
	for ll in langs.keys():
		print(f"{ll}. {langs[ll]}")
	ch = input("Enter the number of your language: ")
	try:
		lang = langs[int(ch)]
	except:
		print("Invalid entry. Try again.")
		return get_lang()
	WORD_LIST = []
	with open("%s/%s.txt" % (get_directory(), lang), "r", encoding="utf-8") as f:
		WORD_LIST = [w.strip() for w in f.readlines()]
	print(f"You selected: {lang}\n")
	return lang, WORD_LIST

def get_word_count():
	print("Select Seed Length: ")
	print(f"Possible Lengths: {[int(s/11) for s in seed.CS_STRENGTHS]} words")
	try:
		n = int(input("How many words were in your seed? "))
	except ValueError:
		print("Invalid entry.")
		return get_word_count()
	if n * 11 not in seed.CS_STRENGTHS:
		print("Invalid Length.")
		return get_word_count()
	print("\n")
	return n

def display_seed_words(seed_words):
	for i, w in enumerate(seed_words):
		print(f"{i+1}. {w}")

def get_seed_words(WORD_LIST):
	word_count = get_word_count()
	print("SEED WORDS: ")
	print(f"Enter seed words about which you are 100{'%'} confident. Each word must be in its correct positioning.")
	print("Do not capitalize any words. Hit ENTER if you do not know the word. Do not include your passphrase.")
	seed_words = [""] * word_count

	for widx in range(word_count):
		new_word = input(f"{widx+1}. ")
		new_word = new_word.strip().lower()
		if new_word != "":
			if new_word in WORD_LIST:
				seed_words[widx] = new_word
	print("\n")
	return verify_seed_words(seed_words, WORD_LIST)

def verify_seed_words(seed_words, WORD_LIST):
	#print results for user to confirm
	print("Please verify your entries. Any mistakes will render this program unable to find your wallet.")
	print("If in doubt about a word or its order, leave it blank.")
	display_seed_words(seed_words)
	ch0 = input("Are you sure about all of the above words? [Y/n] ")
	if ch0.lower() in ["n", "no"]:
		ch1 = -1
		while ch1 != "Q":
			print("Enter the number of the word you wish to replace")
			print("Hit \"Q\" if you are done editing your mnemonic phrase")
			ch1 = input("or enter \"R\" to re-enter all words: ")
			if ch1.upper() == "Q":
				return verify_seed_words(seed_words, WORD_LIST)
			if ch1.upper() == "R":
				return get_seed_words(WORD_LIST)
			try:
				ch1_n = int(ch1)
				if ch1_n > 0 and ch1_n <= len(seed_words):
					new_word = input(f"Enter correct word for word #{ch1} or hit ENTER to leave it blank: ")
					new_word = new_word.strip()
					if new_word != "":
						if new_word in WORD_LIST:
							seed_words[ch1_n-1] = new_word
						else:
							print("Invalid word. Try Again.")
			except ValueError:
				print("invalid selection. Try Again.")
		return verify_seed_words(seed_words, WORD_LIST)
	print("\n")
	return seed_words, get_missing_words(seed_words), len(seed_words)//3

def get_missing_words(seed_words):
	missing_words = []
	for i, w in enumerate(seed_words):
		if w == "":
			missing_words.append(i)
	return missing_words

def get_passphrase():
	print("If you added a passphrase to your mnemonic phrase, enter it here. \
			If you added a password but don't remember it, this process is hopeless.")
	ch = input("If you did not use a passphrase, hit ENTER.")
	return ch

def get_gap_limit():
	MAX = 200
	DEFAULT = 10
	print(f"What gap limit would you like to search? (Default: {DEFAULT})")
	print(f"Note: The larger the gap limit, the longer this will take. MAX: {MAX}.")
	gl = input("Enter Gap Limit: ")
	if gl == '':
		return DEFAULT
	gl = int(gl)
	if gl > MAX or gl <= 0:
		print(f"Error: invalid gap limit. MAX is {MAX}. Try Again.")
		return get_gap_limit()
	return gl

def get_script_type():
	supported_types = ["P2PKH"]
	msg = f"""
		SCRIPT TYPE:
		Please select your script type if you know it. Supported Script types include
		{supported_types} for now. SegWit scripts will be supported soon. If you don't know 
		what a script type is, P2PKH scripts yield an address that starts with a 1, while P2SH 
		script addresses start with a 3. 
		"""
	return supported_types[0]

def get_addresses():
	addrs = []
	msg = """Input as many addresses as you know. Knowing at least one of these will greatly accelerate the process.
If you know many, try to order them chronologically by when you generated/used them, but enter them all.
Type `file` to load a list of addresses from a file, and type `done` when you have entered all known addresses.
		"""
	print(msg.strip())
	while True:
		ch = input("Enter an address: ")
		if ch.lower() == "done" or ch.lower() == "":
			return set(addrs)
		if ch.lower() == "file":
			raise NotImplementedError("File Loading Coming Soon")
		if address_check(ch.strip()):
			addrs.append(ch)
		else:
			print("\nInvalid entry. Try again. Type `done` to move on.\n")

def confirm():
	msg = """
You have entered all useful info. The program will now begin attempting to brute force your seed.
There is no guarantee that this will succeed, and it will take up an unknown amount of processing power and time.
The more words you entered, the shorter and easier this will be. Each missing word makes this process 2048x harder.
If you entered less than half of your words, it's probably not worth trying. You can kill this program with Ctrl + C
or Ctrl + D at any time. Best of luck!!
"""
	print(msg.strip())
	proceed = input("Are you sure you would like to proceed? [Y/n] ")
	print("\n")
	if proceed.lower() not in ["n", "no"]:
		return True
	return False

def fill_bits(given, missing, missing_words):
	guess = given
	for idx, mw in enumerate(missing_words):
		guess[mw*11:mw*11+11] = missing[idx*11:idx*11+11]
	return guess
	
def check_sum(bits, cs_len):
	entropy = bits[:cs_len]
	checksum = bits[cs_len:]
	chash = sha256(entropy.tobytes()).digest()
	#TOOPT: Maybe switch this back? see seed.check_sum()
	return checksum.to01() == bin(int.from_bytes(chash, 'big'))[2:].zfill(256)[:cs_len]

def feeling_lucky(maximum):
	i = input("Are you feeling lucky? Pick a number to start guessing from. Hit ENTER to start at zero. ")
	try:
		ii = int(i)
		return ii
	except ValueError:
		return 0

def full_validate(bits, gap_limit, passphrase, addrs):
	seed = seed.Seed.from_bits(bits.to01())
	wallet = Wallet(passphrase=passphrase, data=seed)
	pkset = wallet.generate_x_keys(gap_limit)
	if pkset & addrs:
		print("\n\n======= SUCCESSS =========\n") 
		print(f"XPub: {wallet.master_xpub}")
		print(f"Xprv: {wallet.master_xprv}")
		print(f"Seed: {seed}")
		print(f"\nMnemonic Phrase:")
		mnemonic = seed.mnemonic()
		for idx, word in enumerate(mnemonic):
			print(f"{idx}. {word}")
		print("You got lucky!! Next time, keep your mnemonic phrase safe.")
		print("\n\nGoodbye.")
		exit(0)


def main():
	# LOAD WORD_LIST of user specified lang
	lang, WORD_LIST = get_lang()
	# print(WORD_LIST[0:4])
	# user sets gap limit
	gap_limit = get_gap_limit()
	# print(gap_limit)
	# user sets script type (non-SegWit)
	script_type = get_script_type()
	# optional passphrase
	passphrase = get_passphrase()

	# get all words users knows
	seed_words, missing_words, cs_len = get_seed_words(WORD_LIST)

	# get all addresses the user knows
	addrs = get_addresses()

	#initialize empty bitarray
	bitstr = []
	try:
		if lang == "english":
			bitstr = map(lambda word: bin(binary_search(WORD_LIST, word))[2:].zfill(11), seed_words)
		else:
			bitstr = map(lambda word: bin(WORD_LIST.index(word)[2:].zfill(11)), seed_words)
	except ValueError:
		print("Error: Invalid Mnemonic Phrase")
		return
	given = bitarray("".join(bitstr))

	if not confirm():
		print("\nGoodbye!\n")
		return 
	
	# start guessing
	len_missing_bits = len(missing_words) * 11
	starter = 3
	incr = 2 
	missing_bits = bitarray("1".zfill(len_missing_bits))
	while(True):
		bits = fill_bits(given, missing_bits, missing_words)
		if check_sum(bits, cs_len):
			full_validate(bits, gap_limit, passphrase, addrs)
		missing_bits.append(0)		
		if missing_bits.pop(0):
			missing_bits = bitarray(bin(starter)[2:].zfill(len_missing_bits))
			starter += incr
			


if __name__ == "__main__":
	main()
