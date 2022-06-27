import pytest
import src.AES_Module.AES as AES


@pytest.mark.parametrize("test_input,test_input_2,expected", [
    (0, 16, 16),
    (16, 32, 32),
    (32, 48, 48),
    (48, 64 , 64),
    (64, 80 , 80),
    (80, 96 , 96),
    (96, 112, 112),

])
def test_aes_actions(test_input, test_input_2, expected):
    assert AES.Actions.progress_bar(None, test_input, test_input_2) is expected
