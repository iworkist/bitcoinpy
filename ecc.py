import util as ut
import hashlib
import hmac
from io import BytesIO

# secp256k1
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
P = 2 ** 256 - 2 ** 32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def mod_add(a, b):
    return (a + b) % P


def mod_sub(a, b):
    return (a - b) % P


def mod_mul(a, b):
    return (a * b) % P


def mod_div(a, b):
    return (a * pow(b, P - 2, P)) % P


def mod_pow(a, exponent):
    return pow(a, exponent % (P - 1), P)


def mod_sqrt(a):
    return mod_pow(a, (P + 1) // 4)


def ecc_add(x1, y1, x2, y2):
    # Case 0.0: self is the point at infinity, return other
    if x1 is None:
        return x2, y2
    # Case 0.1: other is the point at infinity, return self
    if x2 is None:
        return x1, y1

    # Case 1: self.x == other.x, self.y != other.y
    # Result is point at infinity
    # if x1 == x2 and y1 != y2:
    if x1 == x2 and y1 != y2:
        return None, None

    # Case 2: self.x ≠ other.x
    # Formula (x3,y3)==(x1,y1)+(x2,y2)
    # s=(y2-y1)/(x2-x1)
    # x3=s**2-x1-x2
    # y3=s*(x1-x3)-y1
    if x1 != x2:
        s = mod_div(mod_sub(y2, y1), mod_sub(x2, x1))
        x = mod_sub(mod_sub(mod_pow(s, 2), x1), x2)
        y = mod_sub(mod_mul(s, mod_sub(x1, x)), y1)
        return x, y

    # Case 4: if we are tangent to the vertical line,
    # we return the point at infinity
    # note instead of figuring out what 0 is for each type
    # we just use 0 * self.x
    if x1 == x2 and y1 == y2 and y1 == 0:
        return None, None

    # Case 3: self == other
    # Formula (x3,y3)=(x1,y1)+(x1,y1)
    # s=(3*x1**2+a)/(2*y1)
    # x3=s**2-2*x1
    # y3=s*(x1-x3)-y1
    if x1 == x2 and y1 == y2:
        s = mod_div(mod_mul(3, mod_pow(x1, 2)), mod_mul(2, y1))
        x = mod_sub(mod_pow(s, 2), mod_mul(2, x1))
        y = mod_sub(mod_mul(s, mod_sub(x1, x)), y1)
        return x, y


def ecc_mul(n, x=Gx, y=Gy):
    cur = x, y
    res = None, None
    while n:
        if n & 1:
            res = ecc_add(res[0], res[1], cur[0], cur[1])
        cur = ecc_add(cur[0], cur[1], cur[0], cur[1])
        n >>= 1
    return res


def sec(x, y, compressed=True):
    """returns the binary version of the SEC format"""
    if compressed:
        if y % 2 == 0:
            return b'\x02' + x.to_bytes(32, 'big')
        else:
            return b'\x03' + x.to_bytes(32, 'big')
    else:
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def parse_sec(sec_bin):
    """returns a Point object from a SEC binary (not hex)"""
    if sec_bin[0] == 4:
        x = int.from_bytes(sec_bin[1:33], 'big')
        y = int.from_bytes(sec_bin[33:65], 'big')
        return x, y
    is_even = sec_bin[0] == 2
    x = int.from_bytes(sec_bin[1:], 'big')
    # right side of the equation y^2 = x^3 + 7
    # alpha = x ** 3 + 7
    alpha = mod_add(mod_pow(x, 3), 7)

    # solve for left side
    beta = mod_sqrt(alpha)

    if beta % 2 == 0:
        even_beta = beta
        odd_beta = mod_sub(P, beta)
    else:
        even_beta = mod_sub(P, beta.num)
        odd_beta = beta
    if is_even:
        return x, even_beta
    else:
        return x, odd_beta


def wif(sec_key, compressed=True, testnet=False):
    secret_bytes = sec_key.to_bytes(32, 'big')
    if testnet:
        prefix = b'\xef'
    else:
        prefix = b'\x80'
    if compressed:
        suffix = b'\x01'
    else:
        suffix = b''
    return ut.encode_base58_checksum(prefix + secret_bytes + suffix)


def gen_address(sec_key=None):
    # if sec_key is None, generate sec_key randomly.
    if sec_key is None:
        sec_key = "sec_key"

    # gen pub_key
    pub_key = ecc_mul(sec_key)

    # pub_key = sec_key * G
    print('sec_key:', sec_key)

    # not compressed address
    h160 = ut.hash160(sec(pub_key[0], pub_key[1], False))
    address = ut.encode_base58_checksum(b'\x00' + h160)
    address_testnet = ut.encode_base58_checksum(b'\x6f' + h160)

    # compressed address
    h160 = ut.hash160(sec(pub_key[0], pub_key[1], True))
    address_compressed = ut.encode_base58_checksum(b'\x00' + h160)
    address_compressed_testnet = ut.encode_base58_checksum(b'\x6f' + h160)

    res = {
        'sec_key': sec_key,
        'sec_key_wif': wif(sec_key, False, False),
        'sec_key_wif_sec_compressed': wif(sec_key, True, False),
        'sec_key_wif_testnet': wif(sec_key, False, True),
        'sec_key_wif_sec_compressed_test_net': wif(sec_key, True, True),
        'pub_key': pub_key,
        'pub_key_sec': sec(pub_key[0], pub_key[1], False),
        'pub_key_sec_compressed': sec(pub_key[0], pub_key[1]),
        'pub_key_address': address,
        'pub_key_address_testnet': address_testnet,
        'pub_key_address_compressed': address_compressed,
        'pub_key_address_compressed_testnet': address_compressed_testnet
    }

    return res


def deterministic_k(sec_key, z):
    k = b'\x00' * 32
    v = b'\x01' * 32
    if z > N:
        z -= N
    z_bytes = z.to_bytes(32, 'big')
    secret_bytes = sec_key.to_bytes(32, 'big')
    s256 = hashlib.sha256
    k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
    v = hmac.new(k, v, s256).digest()
    k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
    v = hmac.new(k, v, s256).digest()
    while True:
        v = hmac.new(k, v, s256).digest()
        candidate = int.from_bytes(v, 'big')
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b'\x00', s256).digest()
        v = hmac.new(k, v, s256).digest()


def sig(sec_key, z):
    k = deterministic_k(sec_key, z)
    # r is the x coordinate of the resulting point k*G
    r = ecc_mul(k)[0]

    # remember 1/k = pow(k, N-2, N)
    k_inv = pow(k, N - 2, N)
    # s = (z+r*secret) / k
    s = (z + r * sec_key) * k_inv % N
    if s > N / 2:
        s = N - s
    # return an instance of Signature:
    # Signature(r, s)
    return r, s


def sig_der(sig):
    rbin = sig[0].to_bytes(32, byteorder='big')
    # remove all null bytes at the beginning
    rbin = rbin.lstrip(b'\x00')
    # if rbin has a high bit, add a \x00
    if rbin[0] & 0x80:
        rbin = b'\x00' + rbin
    result = bytes([2, len(rbin)]) + rbin
    sbin = sig[1].to_bytes(32, byteorder='big')
    # remove all null bytes at the beginning
    sbin = sbin.lstrip(b'\x00')
    # if sbin has a high bit, add a \x00
    if sbin[0] & 0x80:
        sbin = b'\x00' + sbin
    result += bytes([2, len(sbin)]) + sbin
    return bytes([0x30, len(result)]) + result


def parse_sig_der(signature_bin):
    s = BytesIO(signature_bin)
    compound = s.read(1)[0]
    if compound != 0x30:
        raise SyntaxError("Bad Signature")
    length = s.read(1)[0]
    if length + 2 != len(signature_bin):
        raise SyntaxError("Bad Signature Length")
    marker = s.read(1)[0]
    if marker != 0x02:
        raise SyntaxError("Bad Signature")
    rlength = s.read(1)[0]
    r = int.from_bytes(s.read(rlength), 'big')
    marker = s.read(1)[0]
    if marker != 0x02:
        raise SyntaxError("Bad Signature")
    slength = s.read(1)[0]
    s = int.from_bytes(s.read(slength), 'big')
    if len(signature_bin) != 6 + rlength + slength:
        raise SyntaxError("Signature too long")
    return r, s


def verify_sig(pub_key, sig, z):
    # By Fermat's Little Theorem, 1/s = pow(s, N-2, N)
    s_inv = pow(sig[1], N - 2, N)
    # u = z / s
    u = z * s_inv % N
    # v = r / s
    v = sig[0] * s_inv % N
    # u*G + v*P should have as the x coordinate, r
    p1 = ecc_mul(u)
    p2 = ecc_mul(v, pub_key[0], pub_key[1])
    total = ecc_add(p1[0], p1[1], p2[0], p2[1])
    return total[0] == sig[0]
