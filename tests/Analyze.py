from PyAES.encrypt import encrypt
from PyAES.decrypt import decrypt
from timeit import default_timer as timer
from datetime import timedelta
from random import randint
from os import remove


def test_init(mode, number):
    name = 'T-'
    end = 'B.txt'

    def setup(count):
        for i in range(count):
            i = (8 * i) + 8
            with open(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + str(i) + end, 'wb') as f:
                for j in range(i):
                    f.write(bytes([randint(0, 255)]))

    def clean(count):
        for i in range(count):
            i = (8 * i) + 8
            remove(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + str(i) + end)

    if mode == 'setup':
        setup(number)
    elif mode == 'clean':
        clean(number)


def main():
    # Preform analysis tests
    start = timer()

    # Test 1 - 8 bytes to 5 Gb (ECB) (128 bit key) (* 20)

    # Test 2 - 8 bytes to 5 Gb (CBC) (128 bit key & 128 bit IV) (* 20)

    # Test 3 - 8 bytes to 5 Gb (OFB) (128 bit key & 128 bit IV) (* 20)

    # Test 4 - 8 bytes to 5 Gb (128 bit key & [ECB, CBC, OFB] & [128 bit IV]) (* 20)

    # Test 5 - 8 bytes to 5 Gb (192 bit key & [ECB, CBC, OFB] & [128 bit IV]) (* 20)

    # Test 6 - 8 bytes to 5 Gb (256 bit key & [ECB, CBC, OFB] & [128 bit IV]) (* 20)

    # Test 7 - visualize data (ECB) (128 bit key)

    # Test 8 - visualize data (CBC) (128 bit key & 128 bit IV)

    # Test 9 - visualize data (OFB) (128 bit key & 128 bit IV)

    end = timer()

    # Display time
    print(timedelta(seconds=start - end))


if __name__ == '__main__':
    main()