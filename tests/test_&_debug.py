import pytest
import os
import AES_Module.AES as AES

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

subBytesTable = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )

invSubBytesTable = (
    0x52, 0x09,	0x6a, 0xd5, 0x30, 0x36,	0xa5, 0x38,	0xbf, 0x40,	0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3,	0x39, 0x82, 0x9b, 0x2f,	0xff, 0x87,	0x34, 0x8e,	0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b,	0x94, 0x32, 0xa6, 0xc2,	0x23, 0x3d,	0xee, 0x4c,	0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e,	0xa1, 0x66, 0x28, 0xd9,	0x24, 0xb2,	0x76, 0x5b,	0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8,	0xf6, 0x64, 0x86, 0x68,	0x98, 0x16,	0xd4, 0xa4,	0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70,	0x48, 0x50, 0xfd, 0xed,	0xb9, 0xda,	0x5e, 0x15,	0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8,	0xab, 0x00, 0x8c, 0xbc,	0xd3, 0x0a,	0xf7, 0xe4,	0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c,	0x1e, 0x8f, 0xca, 0x3f,	0x0f, 0x02,	0xc1, 0xaf,	0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91,	0x11, 0x41, 0x4f, 0x67,	0xdc, 0xea,	0x97, 0xf2,	0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac,	0x74, 0x22, 0xe7, 0xad,	0x35, 0x85,	0xe2, 0xf9,	0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1,	0x1a, 0x71, 0x1d, 0x29,	0xc5, 0x89,	0x6f, 0xb7,	0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56,	0x3e, 0x4b, 0xc6, 0xd2,	0x79, 0x20,	0x9a, 0xdb,	0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd,	0xa8, 0x33, 0x88, 0x07,	0xc7, 0x31,	0xb1, 0x12,	0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51,	0x7f, 0xa9, 0x19, 0xb5,	0x4a, 0x0d,	0x2d, 0xe5,	0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0,	0x3b, 0x4d, 0xae, 0x2a,	0xf5, 0xb0,	0xc8, 0xeb,	0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b,	0x04, 0x7e, 0xba, 0x77,	0xd6, 0x26,	0xe1, 0x69,	0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

def test_exist():
    assert AES.__author__ is not None
    assert AES.__copyright__ is not None
    assert AES.__credits__  is not None
    assert AES.__license__ is not None
    assert AES.__version__ is not None
    assert AES.__maintainer__ is not None
    assert AES.__email__ is not None
    assert AES.__status__ is not None

def test_aes_actions_list_to_matrix():
    assert AES.list_to_matrix([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]) == [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]

def test_aes_actions_matrix_to_list():
    assert AES.matrix_to_list([[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]) == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

def test_aes_actions_add_round_key():
    assert AES.add_round_key([[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]) == [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

def test_aes_actions_sub_bytes():
    assert AES.sub_bytes([[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]], subBytesTable) == [[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]

def test_aes_actions_shift_rows():
    assert AES.shift_rows([[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]) == [[99, 107, 103, 118], [242, 1, 171, 123], [48, 215, 119, 197], [254, 124, 111, 43]]

def test_aes_actions_inv_shift_rows():
    assert AES.inv_shift_rows([[99, 107, 103, 118], [242, 1, 171, 123], [48, 215, 119, 197], [254, 124, 111, 43]]) == [[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]

def test_aes_actions_mix_columns():
    assert AES.mix_columns([[0xdb, 0x13, 0x53, 0x45], [0xf2, 0x0a, 0x22, 0x5c], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]) == [[0x8e, 0x4d, 0xa1, 0xbc], [0x9f, 0xdc, 0x58, 0x9d], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]

def test_aes_actions_inv_mix_columns():
    assert AES.inv_mix_columns([[0x8e, 0x4d, 0xa1, 0xbc], [0x9f, 0xdc, 0x58, 0x9d], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]) == [[0xdb, 0x13, 0x53, 0x45], [0xf2, 0x0a, 0x22, 0x5c], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]

def test_aes_key_expantion_128bit():
    round_keys, nr = AES.keyExpansion("00000000000000000000000000000000")

    assert round_keys == [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (98, 99, 99, 99, 98, 99, 99, 99, 98, 99, 99, 99, 98, 99, 99, 99),
        (155, 152, 152, 201, 249, 251, 251, 170, 155, 152, 152, 201, 249, 251, 251, 170),
        (144, 151, 52, 80, 105, 108, 207, 250, 242, 244, 87, 51, 11, 15, 172, 153),
        (238, 6, 218, 123, 135, 106, 21, 129, 117, 158, 66, 178, 126, 145, 238, 43),
        (127, 46, 43, 136, 248, 68, 62, 9, 141, 218, 124, 187, 243, 75, 146, 144),
        (236, 97, 75, 133, 20, 37, 117, 140, 153, 255, 9, 55, 106, 180, 155, 167),
        (33, 117, 23, 135, 53, 80, 98, 11, 172, 175, 107, 60, 198, 27, 240, 155),
        (14, 249, 3, 51, 59, 169, 97, 56, 151, 6, 10, 4, 81, 29, 250, 159),
        (177, 212, 216, 226, 138, 125, 185, 218, 29, 123, 179, 222, 76, 102, 73, 65),
        (180, 239, 91, 203, 62, 146, 226, 17, 35, 233, 81, 207, 111, 143, 24, 142)
        ]
    assert nr == 11

def test_aes_key_expantion_192bit():
    round_keys, nr = AES.keyExpansion("000000000000000000000000000000000000000000000000")

    assert round_keys == [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 0, 0, 0, 0, 98, 99, 99, 99, 98, 99, 99, 99),
        (98, 99, 99, 99, 98, 99, 99, 99, 98, 99, 99, 99, 98, 99, 99, 99),
        (155, 152, 152, 201, 249, 251, 251, 170, 155, 152, 152, 201, 249, 251, 251, 170),
        (155, 152, 152, 201, 249, 251, 251, 170, 144, 151, 52, 80, 105, 108, 207, 250),
        (242, 244, 87, 51, 11, 15, 172, 153, 144, 151, 52, 80, 105, 108, 207, 250),
        (200, 29, 25, 169, 161, 113, 214, 83, 83, 133, 129, 96, 88, 138, 45, 249),
        (200, 29, 25, 169, 161, 113, 214, 83, 123, 235, 244, 155, 218, 154, 34, 200),
        (137, 31, 163, 168, 209, 149, 142, 81, 25, 136, 151, 248, 184, 249, 65, 171),
        (194, 104, 150, 247, 24, 242, 180, 63, 145, 237, 23, 151, 64, 120, 153, 198),
        (89, 240, 14, 62, 225, 9, 79, 149, 131, 236, 188, 15, 155, 30, 8, 48),
        (10, 243, 31, 167, 74, 139, 134, 97, 19, 123, 136, 95, 242, 114, 199, 202),
        (67, 42, 200, 134, 216, 52, 192, 182, 210, 199, 223, 17, 152, 76, 89, 112)
        ]
    assert nr == 13

def test_aes_key_expansion_256bit():
    round_keys, nr = AES.keyExpansion("0000000000000000000000000000000000000000000000000000000000000000")

    assert round_keys == [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (98, 99, 99, 99, 98, 99, 99, 99, 98, 99, 99, 99, 98, 99, 99, 99),
        (170, 251, 251, 251, 170, 251, 251, 251, 170, 251, 251, 251, 170, 251, 251, 251),
        (111, 108, 108, 207, 13, 15, 15, 172, 111, 108, 108, 207, 13, 15, 15, 172),
        (125, 141, 141, 106, 215, 118, 118, 145, 125, 141, 141, 106, 215, 118, 118, 145),
        (83, 84, 237, 193, 94, 91, 226, 109, 49, 55, 142, 162, 60, 56, 129, 14),
        (150, 138, 129, 193, 65, 252, 247, 80, 60, 113, 122, 58, 235, 7, 12, 171),
        (158, 170, 143, 40, 192, 241, 109, 69, 241, 198, 227, 231, 205, 254, 98, 233),
        (43, 49, 43, 223, 106, 205, 220, 143, 86, 188, 166, 181, 189, 187, 170, 30),
        (100, 6, 253, 82, 164, 247, 144, 23, 85, 49, 115, 240, 152, 207, 17, 25),
        (109, 187, 169, 11, 7, 118, 117, 132, 81, 202, 211, 49, 236, 113, 121, 47),
        (231, 176, 232, 156, 67, 71, 120, 139, 22, 118, 11, 123, 142, 185, 26, 98),
        (116, 237, 11, 161, 115, 155, 126, 37, 34, 81, 173, 20, 206, 32, 212, 59),
        (16, 248, 10, 23, 83, 191, 114, 156, 69, 201, 121, 231, 203, 112, 99, 133)
        ]
    assert nr == 15

@pytest.mark.parametrize("data,key,expected", [
    # 128 bit
    ("6bc1bee22e409f96e93d7e117393172a", "2b7e151628aed2a6abf7158809cf4f3c", "3ad77bb40d7a3660a89ecaf32466ef97"),
    ("ae2d8a571e03ac9c9eb76fac45af8e51", "2b7e151628aed2a6abf7158809cf4f3c", "f5d3d58503b9699de785895a96fdbaaf"),
    ("30c81c46a35ce411e5fbc1191a0a52ef", "2b7e151628aed2a6abf7158809cf4f3c", "43b1cd7f598ece23881b00e3ed030688"),
    ("f69f2445df4f9b17ad2b417be66c3710", "2b7e151628aed2a6abf7158809cf4f3c", "7b0c785e27e8ad3f8223207104725dd4"),
    # 192 bit
    ("6bc1bee22e409f96e93d7e117393172a", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "bd334f1d6e45f25ff712a214571fa5cc"),
    ("ae2d8a571e03ac9c9eb76fac45af8e51", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "974104846d0ad3ad7734ecb3ecee4eef"),
    ("30c81c46a35ce411e5fbc1191a0a52ef", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "ef7afd2270e2e60adce0ba2face6444e"),
    ("f69f2445df4f9b17ad2b417be66c3710", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "9a4b41ba738d6c72fb16691603c18e0e"),
    # 256 bit
    ("6bc1bee22e409f96e93d7e117393172a", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
    ("ae2d8a571e03ac9c9eb76fac45af8e51", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "591ccb10d410ed26dc5ba74a31362870"),
    ("30c81c46a35ce411e5fbc1191a0a52ef", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "b6ed21b99ca6f4f9f153e7b1beafed1d"),
    ("f69f2445df4f9b17ad2b417be66c3710", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "23304b7a39f9f3ff067d8d8f9e24ecc7"),
])
def test_aes_encryption_rounds(data, key, expected):
    data = [data[i:i+2] for i in range(0, len(data), 2)]

    for i, t in enumerate(data):
        data[i] = int(t, 16)

    result = AES.encryption_rounds(data, key)

    for i, t in enumerate(result):
        result[i] = hex(t)[2:]
        if len(result[i]) == 1:
            result[i] = "0" + result[i]

    result = "".join(result)

    assert result == expected

@pytest.mark.parametrize("data,key,expected", [
    # 128 bit
    ("3ad77bb40d7a3660a89ecaf32466ef97", "2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a"),
    ("f5d3d58503b9699de785895a96fdbaaf", "2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51"),
    ("43b1cd7f598ece23881b00e3ed030688", "2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef"),
    ("7b0c785e27e8ad3f8223207104725dd4", "2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710"),
    # 192 bit
    ("bd334f1d6e45f25ff712a214571fa5cc", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a"),
    ("974104846d0ad3ad7734ecb3ecee4eef", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "ae2d8a571e03ac9c9eb76fac45af8e51"),
    ("ef7afd2270e2e60adce0ba2face6444e", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "30c81c46a35ce411e5fbc1191a0a52ef"),
    ("9a4b41ba738d6c72fb16691603c18e0e", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f69f2445df4f9b17ad2b417be66c3710"),
    # 256 bit
    ("f3eed1bdb5d2a03c064b5a7e3db181f8", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a"),
    ("591ccb10d410ed26dc5ba74a31362870", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "ae2d8a571e03ac9c9eb76fac45af8e51"),
    ("b6ed21b99ca6f4f9f153e7b1beafed1d", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "30c81c46a35ce411e5fbc1191a0a52ef"),
    ("23304b7a39f9f3ff067d8d8f9e24ecc7", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f69f2445df4f9b17ad2b417be66c3710"),
])
def test_aes_decryption_rounds(data, key, expected):
    data = [data[i:i+2] for i in range(0, len(data), 2)]

    for i, t in enumerate(data):
        data[i] = int(t, 16)

    result = AES.decryption_rounds(data, key)

    for i, t in enumerate(result):
        result[i] = hex(t)[2:]
        if len(result[i]) == 1:
            result[i] = "0" + result[i]

    result = "".join(result)

    assert result == expected

@pytest.mark.parametrize("data,key,file_name,expected", [
    # 128 bit
    (b'1234567890', "2b7e151628aed2a6abf7158809cf4f3c", "tmp.txt", b'|\x94\x18\xcf\x1c\xf0\xef\xa0\xff\xa4\xbb\xe9\xd8\x8am\xa40f\xe4\x1eg\x9d\x88\xb8\xef\xeb{=J\xf3\xf6\xc1'),
    (b'1234567890123456', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8}\xf7k\x0c\x1a\xb8\x99\xb3>B\xf0G\xb9\x1bTo'),
    # 192 bit
    (b'1234567890', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp2.txt", b'K\x9d\xe5\xe9l8&\xdalO\xbb\xc3\xf2\xc3*\xf2\xfe\x9a\xbd!U\x9d\xf3\xaa\x8a\xb2\xac\x96@jyU'),
    (b'1234567890123456', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", b'\xf9\x01\xd7\xe8\xdc\xf7\\\xc0\xc8\xa1*>t\xabA\xd8"E-\x8eI\xa8\xa5\x93\x9fs!\xce\xeamQK'),
    # 256 bit
    (b'1234567890', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp4.txt", b'2 ?\xebm\xf5o\xc2\x8b\x90\x80\x84 D\xc4\x95\x89\x18\n\xeb\xac\xde\xa7P>Ei\xbc|\x9c\xfa\xf2'),
    (b'1234567890123456', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", b"\x8cc'\xc8d\x82\xb3\x8cj\xd2\\\xaa\x96\xf1\xffi\xe5h\xf6\x81\x94\xcfv\xd6\x17ML\xc0C\x10\xa8T")
])
def test_aes_encrypt_ECB(data, key, file_name, expected):
    with open(file_name, "wb") as file:
        file.write(data)

    AES.encrypt(key, file_name, "ECB")

    with open(f"{file_name}.enc", "rb") as file:
        result = file.read()

    os.remove(f"{file_name}.enc")

    assert result == expected

@pytest.mark.parametrize("data,key,file_name,expected", [
    # 128 bit
    (b'|\x94\x18\xcf\x1c\xf0\xef\xa0\xff\xa4\xbb\xe9\xd8\x8am\xa40f\xe4\x1eg\x9d\x88\xb8\xef\xeb{=J\xf3\xf6\xc1', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", b'1234567890'),
    (b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8}\xf7k\x0c\x1a\xb8\x99\xb3>B\xf0G\xb9\x1bTo', "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", b'1234567890123456'),
    (b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8\x93\xb1N\xa8\x13I\xd8\xae\xdaw\xee\xef\xdc\xac\xc2\xdb\xf2\x01\xfa.\x10P\x87\xf27Q\xf7\xf5\x86\xb40\xd3', "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", b'12345678901234567890'),
    # 192 bit
    (b'K\x9d\xe5\xe9l8&\xdalO\xbb\xc3\xf2\xc3*\xf2\xfe\x9a\xbd!U\x9d\xf3\xaa\x8a\xb2\xac\x96@jyU', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", b'1234567890'),
    (b'\xf9\x01\xd7\xe8\xdc\xf7\\\xc0\xc8\xa1*>t\xabA\xd8"E-\x8eI\xa8\xa5\x93\x9fs!\xce\xeamQK', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", b'1234567890123456'),
    # 256 bit
    (b'2 ?\xebm\xf5o\xc2\x8b\x90\x80\x84 D\xc4\x95\x89\x18\n\xeb\xac\xde\xa7P>Ei\xbc|\x9c\xfa\xf2', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", b'1234567890'),
    (b"\x8cc'\xc8d\x82\xb3\x8cj\xd2\\\xaa\x96\xf1\xffi\xe5h\xf6\x81\x94\xcfv\xd6\x17ML\xc0C\x10\xa8T", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", b'1234567890123456')
])
def test_aes_decryption_ECB(data, key, file_name, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    AES.decrypt(key, f"{file_name}.enc", "ECB")

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected

def test_aes_decryption_exeption():
    with pytest.raises(Exception) as e:
        AES.decrypt("1234567890123456", "tmp.txt", "ECB")
    assert str(e.value) == 'File is not encrypted in known format'
    assert e.type == Exception

def test_aes_running_mode_exeption():
    with pytest.raises(Exception) as e:
        AES.encrypt("1234567890123456", "tmp.txt", "a<wertygraewtg")
    assert str(e.value) == 'Running mode not supported'
    assert e.type == Exception

    with pytest.raises(Exception) as p:
        AES.decrypt("1234567890123456", "tmp.txt", "wrseyhstehy")
    assert str(p.value) == 'Running mode not supported'
    assert p.type == Exception

def test_aes_remove_padding_exeption():
    with pytest.raises(Exception) as e:
        AES.remove_padding("2", [17])
    assert str(e.value) == 'Invalid padding'
    assert e.type == ValueError