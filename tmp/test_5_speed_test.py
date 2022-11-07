from random import randint
from time import perf_counter
from PyAES.encrypt import encrypt
from os import remove


def setup(count):
        with open("test_speed.txt", 'wb') as f:
            for j in range(count):
                f.write(bytes([randint(0, 255)]))


def speed_test(count):
    setup(count)
    start = perf_counter()
    encrypt("2b7e151628aed2a6abf7158809cf4f3c", "test_speed.txt", "ECB", iv="000102030405060708090a0b0c0d0e0f")
    end = perf_counter()
    remove("test_speed.txt.enc")
    return end - start

if __name__ == '__main__':
    result = speed_test(100000)
    print(f'Time: {result} seconds')
