import pytest
import AES_Module.AES as AES

def test_aes_decryption_exeption():
    with pytest.raises(Exception) as e:
        AES.decrypt("1234567890123456", "tmp.txt", "ECB")
    assert str(e.value) == 'File is not encrypted in known format'
    assert e.type == Exception

    with pytest.raises(Exception) as e:
        AES.decrypt("1234567890123456", "tmp.txt.enc", "CBC")
    assert str(e.value) == 'Key length is not valid'
    assert e.type == Exception

def test_aes_encryption_exeption():
    with pytest.raises(Exception) as e:
        AES.encrypt("123456789012345", "tmp.txt", "CBC")
    assert str(e.value) == 'Key length is not valid'
    assert e.type == Exception

    with pytest.raises(Exception) as e:
        AES.encrypt("1234567890123456", "tmp.txt", "ECB")
    assert str(e.value) == 'Key length is not valid'
    assert e.type == Exception

def test_aes_running_mode_exeption():
    with pytest.raises(Exception) as e:
        AES.encrypt("12345678901234567890123456789012", "tmp.txt", "a<wertygraewtg")
    assert str(e.value) == 'Running mode not supported'
    assert e.type == Exception

    with pytest.raises(Exception) as p:
        AES.decrypt("12345678901234567890123456789012", "tmp.txt.enc", "wrseyhstehy")
    assert str(p.value) == 'Running mode not supported'
    assert p.type == Exception

def test_aes_remove_padding_exeption():
    with pytest.raises(Exception) as e:
        AES.remove_padding("2", [17])
    assert str(e.value) == 'Invalid padding'
    assert e.type == ValueError