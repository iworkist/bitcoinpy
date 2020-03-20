import ecc
import random

sec_key = int(random.random() * 10 ** 30)
address = ecc.gen_address(sec_key)
print(address)
# address = {
#     'sec_key': sec_key,
#     'sec_key_wif': wif(sec_key, False, False),
#     'sec_key_wif_sec_compressed': wif(sec_key, True, False),
#     'sec_key_wif_testnet': wif(sec_key, False, True),
#     'sec_key_wif_sec_compressed_test_net': wif(sec_key, True, True),
#     'pub_key': pub_key,
#     'pub_key_sec': sec(pub_key[0], pub_key[1], False),
#     'pub_key_sec_compressed': sec(pub_key[0], pub_key[1]),
#     'pub_key_address': address,
#     'pub_key_address_testnet': address_testnet,
#     'pub_key_address_compressed': address_compressed,
#     'pub_key_address_compressed_testnet': address_compressed_testnet
# }

sig = ecc.sig(sec_key, 999)
print('sig', sig)
print('der', ecc.der(sig))

res = ecc.verify_sig(address['pub_key'], sig, 999)
print('sig_verification', res)
