import merkletree as mt
import network


def test_init():
    tree = mt.MerkleTree(9)
    assert len(tree.nodes[0]) == 1
    assert len(tree.nodes[1]) == 2
    assert len(tree.nodes[2]) == 3
    assert len(tree.nodes[3]) == 5
    assert len(tree.nodes[4]) == 9


def test_populate_tree_1():
    hex_hashes = [
        "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
        "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
        "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
        "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
        "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
        "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
        "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
        "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
        "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
        "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
        "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
        "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
        "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
        "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
        "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
        "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
    ]
    tree = mt.MerkleTree(len(hex_hashes))
    hashes = [bytes.fromhex(h) for h in hex_hashes]
    tree.populate_tree([1] * 31, hashes)
    root = '597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1'
    assert tree.root().hex() == root


def test_populate_tree_2():
    hex_hashes = [
        '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
        '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
        '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
        'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
        '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    ]
    tree = mt.MerkleTree(len(hex_hashes))
    hashes = [bytes.fromhex(h) for h in hex_hashes]
    tree.populate_tree([1] * 11, hashes)
    root = 'a8e8bd023169b81bc56854137a135b97ef47a6a7237f4c6e037baed16285a5ab'
    assert tree.root().hex() == root


def test_merkle_parent_level():
    hex_hashes = [
        'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
        'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
        'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
        '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
        '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
        '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
        '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
        'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
        'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
        '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
        '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
    ]
    tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
    want_hex_hashes = [
        '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
        '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
        'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
        '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
        '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
        '1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10',
    ]
    want_tx_hashes = [bytes.fromhex(x) for x in want_hex_hashes]
    assert mt.merkle_parent_level(tx_hashes) == want_tx_hashes


def test_merkle_root():
    hex_hashes = [
        'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
        'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
        'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
        '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
        '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
        '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
        '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
        'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
        'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
        '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
        '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
        'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
    ]
    tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
    want_hex_hash = 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6'
    want_hash = bytes.fromhex(want_hex_hash)
    assert mt.merkle_root(tx_hashes) == want_hash


def test_merkle_parent():
    tx_hash0 = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
    tx_hash1 = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
    want = bytes.fromhex('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')
    assert mt.merkle_parent(tx_hash0, tx_hash1) == want



test_init()
test_populate_tree_1()
test_populate_tree_2()
test_merkle_parent_level()
test_merkle_root()
test_merkle_parent()
