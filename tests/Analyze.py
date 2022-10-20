from PyAES.encrypt import encrypt
from timeit import default_timer as timer
from random import randint
from os import remove
import csv


def test_init(mode, number):
    name = 'T-'
    end = 'B.txt'

    def setup(count):
        with open(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + str(count) + end, 'wb') as f:
            for j in range(count):
                f.write(bytes([randint(0, 255)]))

    def clean(count):
        remove(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + str(count) + end + '.enc')

    if mode == 'setup':
        setup(number)
    elif mode == 'clean':
        clean(number)


def write_data(data, name):
    with open(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + '.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(data)


def test_encrypt(name, key, sizes, running_mode, iv=None, terminal_size=80, iterations=None):
    test = []
    for i in range(iterations):
        test_0 = []
        for i in range(len(sizes)):
            test_init('setup', sizes[i])
            start = timer()
            encrypt(key, r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/T-' + str(sizes[i]) + 'B.txt', running_mode, iv=iv, terminal_size=terminal_size)
            end = timer()
            test_init('clean', sizes[i])
            test_0.append(end - start)
        test.append(test_0)
    write_data(test, name)


def main():
    # Core variables
    key_128 = "2b7e151628aed2a6abf7158809cf4f3c"
    key_192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = "000102030405060708090a0b0c0d0e0f"
    sizes = [(2**3), (2**5), (2**7), (2**9), (2**11), (2**13), (2**15), (2**17), (2**19), (2**21), (2**23), (2**25), (2**27), (2**29), (2**31)]

    # Test 1 - 8 bytes to 2 Gb (128 bit key & [ECB, CBC, OFB] & [128 bit IV]) (* 10)
    test_encrypt("test_1_ECB", key_128, sizes, 'ECB', iterations=20)
    test_encrypt("test_1_CBC", key_128, sizes, 'CBC', iv=iv, iterations=20)
    test_encrypt("test_1_OFB", key_128, sizes, 'OFB', iv=iv, iterations=20)

    ## Test 2 - 8 bytes to 2 Gb (192 bit key & [ECB, CBC, OFB] & [128 bit IV]) (* 10)
    test_encrypt("test_2_ECB", key_192, sizes, 'ECB', iterations=20)
    test_encrypt("test_2_CBC", key_192, sizes, 'CBC', iv=iv, iterations=20)
    test_encrypt("test_2_OFB", key_192, sizes, 'OFB', iv=iv, iterations=20)

    ## Test 3 - 8 bytes to 2 Gb (256 bit key & [ECB, CBC, OFB] & [128 bit IV]) (* 10)
    test_encrypt("test_3_ECB", key_256, sizes, 'ECB', iterations=20)
    test_encrypt("test_3_CBC", key_256, sizes, 'CBC', iv=iv, iterations=20)
    test_encrypt("test_3_OFB", key_256, sizes, 'OFB', iv=iv, iterations=20)


if __name__ == '__main__':
    main()
