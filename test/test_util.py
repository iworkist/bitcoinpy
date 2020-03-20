import util


def test_little_endian_to_int():
    h = bytes.fromhex('99c3980000000000')
    want = 10011545
    assert util.little_endian_to_int(h) == want
    h = bytes.fromhex('a135ef0100000000')
    want = 32454049
    assert util.little_endian_to_int(h) == want


def test_int_to_little_endian():
    n = 1
    want = b'\x01\x00\x00\x00'
    assert util.int_to_little_endian(n, 4) == want
    n = 10011545
    want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
    assert util.int_to_little_endian(n, 8) == want


def test_base58():
    addr = 'mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf'
    h160 = util.decode_base58(addr).hex()
    want = '507b27411ccf7f16f10297de6cef3f291623eddf'
    assert h160 == want
    got = util.encode_base58_checksum(b'\x6f' + bytes.fromhex(h160))
    assert got == addr


def test_p2pkh_address():
    h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
    want = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
    assert util.h160_to_p2pkh_address(h160, testnet=False) == want
    want = 'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'
    assert util.h160_to_p2pkh_address(h160, testnet=True) == want


def test_p2sh_address():
    h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
    want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
    assert util.h160_to_p2sh_address(h160, testnet=False) == want
    want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
    assert util.h160_to_p2sh_address(h160, testnet=True) == want


test_little_endian_to_int()
test_int_to_little_endian()
test_base58()
test_p2pkh_address()
test_p2sh_address()
