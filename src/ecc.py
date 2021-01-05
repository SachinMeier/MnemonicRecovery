
from unittest import TestCase
from io import BytesIO
import hashlib
import hmac
from helper import (
	hash160,
	hash256,
	encode_base58_checksum
)

from random import randint


'''
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
n =  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
p = 2**256 - 2**32 - 977 
y**2 = x**3 + 7
'''

class FieldElement:
	def __init__(self, num, order):

		if num >=order or num < 0:
			error = "Num {} is not in field range 0 to {}".format(num, order-1)
			raise ValueError(error)
		self.num = num
		self.order = order
	def __repr__(self):
		return "FieldElement_{}({})".format(self.order, self.num)

	def __eq__(self, other):
		if other is None:
			return False
		return self.num == other.num and self.order == other.order

	def __ne__(self, other):
		return not (self == other)

	def __add__(self, other):
		if (self.order != other.order):
			raise TypeError("Cannot Add two numbers in different Fields")
		num = ((self.num+other.num)%self.order)
		return self.__class__(num, self.order)
	
	def __sub__(self, other):
		if(self.order != other.order):
			raise TypeError("Cannot Subtract two numbers in different Fields")
		num = ((self.num-other.num) % self.order)
		return self.__class__(num, self.order)

	def __mul__(self, other):
		if (self.order != other.order):
			raise TypeError("Cannot Multiply two numbers in different Fields")
		num = ((self.num * other.num) % self.order)
		return self.__class__(num, self.order)

	def __truediv__(self, other):
			if(self.order != other.order):
				raise TypeError("Cannot Divide two numbers in different Fields")
			num = ( (self.num * pow(other.num, self.order-2, self.order)) % self.order )
			return self.__class__(num, self.order)

	def __rmul__(self, coefficient):
		num = (self.num * coefficient) % self.order
		return self.__class__(num=num, order=self.order)

	def __pow__(self, exponent):
		n = exponent % (self.order - 1)
		num = pow(self.num, n, self.order)   # same as (self.num ** exponent) % self.order
		return self.__class__(num, self.order)

class Point:
	def __init__(self, x, y, a, b):
		self.x = x
		self.y = y
		self.a = a
		self.b = b
		if self.x is None and self.y is None:
			return
		if( self.y**2 != self.x**3 + a*x + b ):
			raise ValueError("({},{}) is not on the Curve. ".format(x, y))


	def __repr__(self):
		if self.x is None:
			return 'Point(infinity)'
		elif isinstance(self.x, FieldElement):
			return 'Point({},{})_{}_{}  FieldElement({})'.format(hex(self.x.num), hex(self.y.num), self.a.num, self.b.num, hex(self.x.order))
		else:
			return 'Point( {},{} )_{}_{}'.format(self.x, self.y, self.a, self.b)

	def __eq__(self, other):
		return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b

	def __ne__(self, other):
		return not (self == other)

	def __add__(self, other):
		if self.a != other.a or self.b != other.b:
			raise TypeError("Points {}, {} are not on the same Curve".format(self, other))
		
		#Adding Identity Point (inf)
		if self.x is None:
			return other
		if other.x is None:
			return self

		#Adding when P1 = P2 and y1 = 0 (tangent and vertical)
		if self == other and self.y == 0 * self.x:
			return self.__class__(None, None, self.a, self.b)

		#Adding Inverse Point (self + other = inf), vertical line
			#same x 				#opposite y
		if (self.x == other.x) and self.y != other.y:
			return self.__class__(None, None, self.a, self.b)
		
		#Adding when X1 ≠ X2    x1 = self  x2 = other
		if self.x != other.x:
			s = (other.y - self.y) / (other.x - self.x)
			x3 = s**2 - self.x - other.x
			y3 = s * (self.x - x3) - self.y
			return self.__class__(x3, y3, self.a, self.b)

		#Adding when P1 = P2   (tangent line)
		if self == other:
			s = ( (3 * self.x**2 + self.a) / (2 * self.y) ) #derivative of ( y**2 = x**3 + ax + b )
			x3 = s**2 - 2 * self.x
			y3 = s * (self.x - x3) - self.y
			return self.__class__(x3, y3, self.a, self.b)

	def __rmul__(self, coefficient):
		coef = coefficient
		current = self  # <1>
		result = self.__class__(None, None, self.a, self.b)  # <2>
		while coef:
		    if coef & 1:  # <3>
		        result += current
		    current += current  # <4>
		    coef >>= 1  # <5>
		return result

# prime number used for Finite Field
P = 2**256 - 2**32 - 977 
# y^2 = x^3 + 7
A = 0
B = 7
#infinite point (N * G) == inf
N =  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class S256Field(FieldElement):
	def __init__(self, num, order=None):
		super().__init__(num, order=P)

	def __repr__(self):
		return '{:x}'.format(self.num).zfill(64)

	def sqrt(self):
		return self**((P + 1) // 4)

class S256Point(Point):
	def __init__(self, x, y, a=None, b=None):
		a = S256Field(A)
		b = S256Field(B)
		if type(x) == int:
			super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
		else:
			super().__init__(x=x, y=y, a=a, b=b)

	def __repr__(self):
		if self.x is None:
			return 'S256Point(infinity)'
		else:
			return 'S256Point({}, {})'.format(self.x, self.y)

	def __rmul__(self, coefficient):
		coef = coefficient % N
		return super().__rmul__(coef)

	def verify(self, z, sig):
		s_inv = pow(sig.s, N-2, N)
		u = z * s_inv % N
		v = sig.r * s_inv % N
		total = u * G + v * self
		return total.x.num == sig.r

	def sec(self, compressed=True):
		'''returns binary version of the SEC format'''
		if compressed:
			if self.y.num%2 == 0:
				return b'\x02' + self.x.num.to_bytes(32, 'big')
			else: 
				return b'\x03' + self.x.num.to_bytes(32, 'big')
		else: 
			return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
	@classmethod
	def parse(cls, sec_bin):
		'''returns a Point object from SEC binary (not hex)'''
		#First, uncompressed format
		if sec_bin[0] == 4:
			x = int.from_bytes(sec_bin[1:33], 'big')
			y = int.from_bytes(sec_bin[33:65], 'big')
			return S256Point(x,y)

		is_even = sec_bin[0] == 2
		x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
		# right side of equation is y^2 = x^3 + 7
		alpha = x**3 + S256Field(B)
		#solve for left side
		beta = alpha.sqrt()
		if beta.num % 2 == 0:
			even_beta = beta
			odd_beta = S256Field(P - beta.num)
		else:
			even_beta = S256Field(P - beta.num)
			odd_beta = beta
		if is_even:
			return S256Point(x, even_beta)   # Why can't this be self.__class__
		else:
			return S256Point(x, odd_beta)    # Why can't this be self.__class__

	def hash160(self, compressed=True):
		return hash160(self.sec(compressed))
	
	def address(self, compressed=True, testnet=False):
		'''Returns address string'''
		h160 = self.hash160(compressed)
		prefix = b'\x00'
		if testnet:
			prefix = b'\x6f'
		return encode_base58_checksum(prefix + h160)

# Generator Point. (secret * G) = PubKey
G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 
	S256Field(A),
	S256Field(B))

class PrivateKey:
	def __init__(self, secret):
		self.secret = secret
		self.point = secret * G

	def hex(self):
		return '{:x}'.format(self.secret).zfill(64)

	def sign(self, z):
		k = self.deterministic_k(z)
		r = (k * G).x.num
		k_inv = pow(k, N-2, N)
		s = (z + r * self.secret) * k_inv % N
		if s > N/2:
			s = N - s
		return Signature(r,s)

	def deterministic_k(self, z):
		k = b'\x00' * 32
		v = b'\x01' * 32
		if z > N:
			z -= N
		z_bytes = z.to_bytes(32, 'big')
		secret_bytes = self.secret.to_bytes(32, 'big')
		s256 = hashlib.sha256
		k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
		v = hmac.new(k, v, s256).digest()
		k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
		v = hmac.new(k, v, s256).digest()
		while True:
			v = hmac.new(k, v, s256).digest()
			candidate = int.from_bytes(v, 'big')
			if candidate >= 1 and candidate < N:
				return candidate
			k = hmac.new(k, v + b'\x00', s256).digest()
			v = hmac.new(k,v,s256).digest()

	def wif(self, compressed=True, testnet=False):
		secret_bytes = self.secret.to_bytes(32, 'big')
		if testnet:
			prefix = b'\xef'
		else:
			prefix = b'\x80'
		if compressed:
			suffix = b'\x01'
		else:
			suffix = b''
		return encode_base58_checksum(prefix + secret_bytes + suffix)

if __name__ == "__main__":
    p = PrivateKey(123414253234542345423623)
    print(p.hex())
    print(p.wif())