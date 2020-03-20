import util
import merkletree as mt


def parse(s):
    result = {}
    result['version'] = util.little_endian_to_int(s.read(4))
    result['prev_block_hash'] = s.read(32)[::-1]
    result['merkle_root'] = s.read(32)[::-1]
    result['timestamp'] = util.little_endian_to_int(s.read(4))
    result['bits'] = s.read(4)
    result['nonce'] = s.read(4)

    return result


def serialize(obj):
    """
     4: version (LE)
    32: prev_block_hash (LE)
    32: merkle_root (LE)
     4: timestamp (LE)
     4: bits
     4: nonce
    """
    result = util.int_to_little_endian(obj['version'], 4)
    result += obj['prev_block_hash'][::-1]
    result += obj['merkle_root'][::-1]
    result += util.int_to_little_endian(obj['timestamp'], 4)
    result += obj['bits']
    result += obj['nonce']
    return result


def hash_header(obj):
    """Returns the hash256 interpreted little endian of the block"""
    s = serialize(obj)
    h256 = util.hash256(s)
    return h256[::-1]


def bip9(obj):
    """Returns whether this block is signaling readiness for BIP9"""
    # BIP9 is signalled if the top 3 bits are 001
    # remember version is 32 bytes so right shift 29 (>> 29) and see if
    # that is 001
    return obj['version'] >> 29 == 0b001


def bip91(obj):
    """Returns whether this block is signaling readiness for BIP91"""
    # BIP91 is signalled if the 5th bit from the right is 1
    # shift 4 bits to the right and see if the last bit is 1
    return obj['version'] >> 4 & 1 == 1


def bip141(obj):
    """Returns whether this block is signaling readiness for BIP141"""
    # BIP91 is signalled if the 2nd bit from the right is 1
    # shift 1 bit to the right and see if the last bit is 1
    return obj['version'] >> 1 & 1 == 1


def target(obj):
    """Returns the proof-of-work target based on the bits"""
    return bits_to_target(obj['bits'])


def difficulty(obj):
    """Returns the block difficulty based on the bits"""
    # note difficulty is (target of lowest difficulty) / (self's target)
    # lowest difficulty has bits that equal 0xffff001d
    lowest = 0xffff * 256 ** (0x1d - 3)
    return lowest / target(obj)


def check_pow(obj):
    """Returns whether this block satisfies proof of work"""
    # get the hash256 of the serialization of this block
    h256 = util.hash256(serialize(obj))
    # interpret this hash as a little-endian number
    proof = util.little_endian_to_int(h256)
    # return whether this integer is less than the target
    return proof < target(obj)


def is_valid_merkle_root(obj):
    """Gets the merkle root of the tx_hashes and checks that it's
    the same as the merkle root of this block.
    """
    # reverse each item in self.tx_hashes
    hashes = [h[::-1] for h in obj['tx_hashes']]
    # compute the Merkle Root and reverse
    root = mt.merkle_root(hashes)[::-1]
    # return whether self.merkle_root is the same
    return root == obj['merkle_root']


def bits_to_target(bits):
    """Turns bits into a target (large 256-bit integer)"""
    # last byte is exponent
    exponent = bits[-1]
    # the first three bytes are the coefficient in little endian
    coefficient = util.little_endian_to_int(bits[:-1])
    # the formula is:
    # coefficient * 256**(exponent-3)
    return coefficient * 256 ** (exponent - 3)


def target_to_bits(target):
    """Turns a target integer back into bits, which is 4 bytes"""
    raw_bytes = target.to_bytes(32, 'big')
    # get rid of leading 0's
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        # if the first bit is 1, we have to start with 00
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        # otherwise, we can show the first 3 bytes
        # exponent is the number of digits in base-256
        exponent = len(raw_bytes)
        # coefficient is the first 3 digits of the base-256 number
        coefficient = raw_bytes[:3]
    # we've truncated the number after the first 3 digits of base-256
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits


TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256 ** (0x1d - 3)


def calculate_new_bits(previous_bits, time_differential):
    """Calculates the new bits given
    a 2016-block time differential and the previous bits"""
    # if the time differential is greater than 8 weeks, set to 8 weeks
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    # if the time differential is less than half a week, set to half a week
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    # the new target is the previous target * time differential / two weeks
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    # convert the new target to bits
    return target_to_bits(new_target)
