import bloomfilter


def test_bit_field_to_bytes():
    bit_field = [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
                 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
    want = '4000600a080000010940'
    assert bloomfilter.bit_field_to_bytes(bit_field).hex() == want
    assert bloomfilter.bytes_to_bit_field(bytes.fromhex(want)) == bit_field


test_bit_field_to_bytes()
