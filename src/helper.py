from unittest import TestCase, TestSuite, TextTestRunner

import hashlib


SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def hash160(s):
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(s):
    return encode_base58(s + hash256(s)[:4])


def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]


def little_to_int(b):
    '''little_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    return int.from_bytes(b, 'little')


def int_to_little(n, length):
    '''endian_to_little takes an integer and returns the little-endian
    byte sequence of length'''
    return n.to_bytes(length, 'little')


def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))


def h160_to_p2pkh_address(h160, testnet=False):
    '''Takes a byte sequence hash160 and returns a p2pkh address string'''
    # p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, testnet=False):
    '''Takes a byte sequence hash160 and returns a p2sh address string'''
    # p2sh has a prefix of b'\x05' for mainnet, b'\xc4' for testnet
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)


def bits_to_target(bits):
    '''Turns bits into a target (large 256-bit integer)'''
    # last byte is exponent
    # the first three bytes are the coefficient in little endian
    # the formula is:
    # coefficient * 256**(exponent-3)
    raise NotImplementedError


# tag::source1[]
def target_to_bits(target):
    '''Turns a target integer back into bits'''
    raw_bytes = target.to_bytes(32, 'big')
    raw_bytes = raw_bytes.lstrip(b'\x00')  # <1>
    if raw_bytes[0] > 0x7f:  # <2>
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)  # <3>
        coefficient = raw_bytes[:3]  # <4>
    new_bits = coefficient[::-1] + bytes([exponent])  # <5>
    return new_bits
# end::source1[]


def calculate_new_bits(previous_bits, time_differential):
    '''Calculates the new bits given
    a 2016-block time differential and the previous bits'''
    # if the time differential is greater than 8 weeks, set to 8 weeks
    # if the time differential is less than half a week, set to half a week
    # the new target is the previous target * time differential / two weeks
    # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
    # convert the new target to bits
    raise NotImplementedError


class HelperTest(TestCase):

    def test_little_to_int(self):
        h = bytes.fromhex('99c3980000000000')
        want = 10011545
        self.assertEqual(little_to_int(h), want)
        h = bytes.fromhex('a135ef0100000000')
        want = 32454049
        self.assertEqual(little_to_int(h), want)

    def test_int_to_little(self):
        n = 1
        want = b'\x01\x00\x00\x00'
        self.assertEqual(int_to_little(n, 4), want)
        n = 10011545
        want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
        self.assertEqual(int_to_little(n, 8), want)

    def test_base58(self):
        addr = 'mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf'
        h160 = decode_base58(addr).hex()
        want = '507b27411ccf7f16f10297de6cef3f291623eddf'
        self.assertEqual(h160, want)
        got = encode_base58_checksum(b'\x6f' + bytes.fromhex(h160))
        self.assertEqual(got, addr)

    def test_p2pkh_address(self):
        h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=False), want)
        want = 'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=True), want)

    def test_p2sh_address(self):
        h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        self.assertEqual(h160_to_p2sh_address(h160, testnet=False), want)
        want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(h160_to_p2sh_address(h160, testnet=True), want)

    def test_calculate_new_bits(self):
        prev_bits = bytes.fromhex('54d80118')
        time_differential = 302400
        want = bytes.fromhex('00157617')
        self.assertEqual(calculate_new_bits(prev_bits, time_differential), want)


"""
Following 4 functions and 3 vars are taken from 
https://github.com/richardkiss/pycoin/tree/master/pycoin/encoding
under the MIT license

"""

def to_long(base, lookup_f, s):
    """
    Convert an array to a (possibly bignum) integer, along with a prefix value
    of how many prefixed zeros there are.
    base:
        the source base
    lookup_f:
        a function to convert an element of s to a value between 0 and base-1.
    s:
        the value to convert
    """
    prefix = 0
    v = 0
    for c in s:
        v *= base
        try:
            v += lookup_f(c)
        except Exception:
            raise EncodingError("bad character %s in string %s" % (c, s))
        if v == 0:
            prefix += 1
    return v, prefix

def from_long(v, prefix, base, charset):
    """The inverse of to_long. Convert an integer to an arbitrary base.
    v: the integer value to convert
    prefix: the number of prefixed 0s to include
    base: the new base
    charset: an array indicating what printable character to use for each value.
    """
    ba = bytearray()
    while v > 0:
        try:
            v, mod = divmod(v, base)
            ba.append(charset(mod))
        except Exception:
            raise EncodingError("can't convert to character corresponding to %d" % mod)
    ba.extend([charset(0)] * prefix)
    ba.reverse()
    return bytes(ba)

BASE58_ALPHABET2 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_BASE = len(BASE58_ALPHABET2)
BASE58_LOOKUP = dict((c, i) for i, c in enumerate(BASE58_ALPHABET2))

def b2a_base58(s):
    """Convert binary to base58 using BASE58_ALPHABET. Like Bitcoin addresses."""
    v, prefix = to_long(256, lambda x: x, iterbytes(s))
    s = from_long(v, prefix, BASE58_BASE, lambda v: BASE58_ALPHABET[v])
    return s.decode("utf8")

def a2b_base58(s):
    """Convert base58 to binary using BASE58_ALPHABET."""
    v, prefix = to_long(BASE58_BASE, lambda c: BASE58_LOOKUP[c], s.encode("utf8"))
    return from_long(v, prefix, 256, lambda x: x)

"""
end source from pycoin
"""