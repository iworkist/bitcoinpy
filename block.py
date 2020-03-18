import util


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
    return util.bits_to_target(obj['bits'])


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

# def validate_merkle_root(obj):
#     """Gets the merkle root of the tx_hashes and checks that it's
#     the same as the merkle root of this block.
#     """
#     # reverse each item in self.tx_hashes
#     hashes = [h[::-1] for h in obj.tx_hashes]
#     # compute the Merkle Root and reverse
#     root = merkle_root(hashes)[::-1]
#     # return whether self.merkle_root is the same
#     return root == self.merkle_root
