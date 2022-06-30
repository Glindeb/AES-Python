import pytest
import AES_Module.AES as AES

aes = AES.Core_data()
aes_a = AES.Actions()
aes_k = AES.Key_expansion()


def test_exist():
    assert AES.__author__ is not None
    assert AES.__copyright__ is not None
    assert AES.__credits__  is not None
    assert AES.__license__ is not None
    assert AES.__version__ is not None
    assert AES.__maintainer__ is not None
    assert AES.__email__ is not None
    assert AES.__status__ is not None

@pytest.mark.parametrize("test_input,test_input_2,expected", [
    (0, 16, 16),
    (16, 32, 32),
    (32, 48, 48),
    (48, 64 , 64),
    (64, 80 , 80),
    (80, 96 , 96),
    (96, 112, 112),

])
def test_aes_actions_progress_bar(test_input, test_input_2, expected):
    assert aes_a.progress_bar(test_input, test_input_2) is expected

def test_aes_actions_error_message():
    assert aes_a.error_message('under testing', 0) is 1

def test_aes_actions_bytes_to_matrix():
    assert aes_a.bytes_to_matrix(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f') == [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]

def test_aes_actions_matrix_to_bytes():
    assert aes_a.matrix_to_bytes([[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]) == b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

def test_aes_actions_list_to_matrix():
    assert aes_a.list_to_matrix([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]) == [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]

def test_aes_actions_matrix_to_list():
    assert aes_a.matrix_to_list([[0x8e, 0x4d, 0xa1, 0xbc], [0x9f, 0xdc, 0x58, 0x9d], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]) == [0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6]

def test_aes_actions_add_round_key():
    assert aes_a.add_round_key([[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]) == [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

def test_aes_actions_sub_bytes():
    assert aes_a.sub_bytes([[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]], aes.subBytesTable) == [[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]

def test_aes_actions_shift_rows():
    assert aes_a.shift_rows([[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]) == [[99, 107, 103, 118], [242, 1, 171, 123], [48, 215, 119, 197], [254, 124, 111, 43]]

def test_aes_actions_inv_shift_rows():
    assert aes_a.inv_shift_rows([[99, 107, 103, 118], [242, 1, 171, 123], [48, 215, 119, 197], [254, 124, 111, 43]]) == [[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]

def test_aes_actions_mix_columns():
    assert aes_a.mix_columns([[0xdb, 0x13, 0x53, 0x45], [0xf2, 0x0a, 0x22, 0x5c], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]) == [[0x8e, 0x4d, 0xa1, 0xbc], [0x9f, 0xdc, 0x58, 0x9d], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]

def test_aes_actions_inv_mix_columns():
    assert aes_a.inv_mix_columns([[0x8e, 0x4d, 0xa1, 0xbc], [0x9f, 0xdc, 0x58, 0x9d], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]) == [[0xdb, 0x13, 0x53, 0x45], [0xf2, 0x0a, 0x22, 0x5c], [0x01, 0x01, 0x01, 0x01], [0xc6, 0xc6, 0xc6, 0xc6]]

def test_aes_key_expansion_word_rotate():
    assert aes_k.word_rotate([0x00, 0x01, 0x02, 0x03]) == [0x01, 0x02, 0x03, 0x00]

def test_aes_key_expansion_word_substitute():
    assert aes_k.word_substitute([0x00, 0x01, 0x02, 0x03]) == [0x63, 0x7c, 0x77, 0x7b]
