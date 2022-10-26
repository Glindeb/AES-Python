from PyAES.encrypt import encrypt
from timeit import default_timer as timer
from random import randint
from os import remove
import csv
from multiprocessing import Process

end_f = 'B.txt'

def test_init(mode, number, name_f):
    def setup(count, name_f):
        with open(name_f + str(count) + end_f, 'wb') as f:
            for j in range(count):
                f.write(bytes([randint(0, 255)]))

    def clean(count, name_f):
        remove(name_f + str(count) + end_f + '.enc')

    if mode == 'setup':
        setup(number, name_f)
    elif mode == 'clean':
        clean(number, name_f)


def write_data(data, name_f):
    with open(name_f + '.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(data)


def test_encrypt(name, key, sizes, running_mode, iv=None, terminal_size=80, iterations=None):
    test = []
    for i in range(iterations):
        test_0 = []
        for i in range(len(sizes)):
            test_init('setup', sizes[i], name)
            start = timer()
            encrypt(key, name + str(sizes[i]) + end_f, running_mode, iv=iv, terminal_size=terminal_size)
            end = timer()
            test_init('clean', sizes[i], name)
            test_0.append(end - start)
        test.append(test_0)
    write_data(test, name)


if __name__ == '__main__':
    # Run in parallel
    key_128 = "2b7e151628aed2a6abf7158809cf4f3c"
    key_192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = "000102030405060708090a0b0c0d0e0f"
    sizes = [(2**3), (2**5), (2**7), (2**9), (2**11), (2**13), (2**15), (2**17), (2**19), (2**21), (2**23), (2**25)]

    p1 = Process(target=test_encrypt, args=("test_1_ECB", key_128, sizes, 'ECB', None, 80, 10))
    p2 = Process(target=test_encrypt, args=("test_1_CBC", key_128, sizes, 'CBC', iv, 80, 10))
    p3 = Process(target=test_encrypt, args=("test_1_OFB", key_128, sizes, 'OFB', iv, 80, 10))

    p4 = Process(target=test_encrypt, args=("test_2_ECB", key_192, sizes, 'ECB', None, 80, 10))
    p5 = Process(target=test_encrypt, args=("test_2_CBC", key_192, sizes, 'CBC', iv, 80, 10))
    p6 = Process(target=test_encrypt, args=("test_2_OFB", key_192, sizes, 'OFB', iv, 80, 10))

    p7 = Process(target=test_encrypt, args=("test_3_ECB", key_256, sizes, 'ECB', None, 80, 10))
    p8 = Process(target=test_encrypt, args=("test_3_CBC", key_256, sizes, 'CBC', iv, 80, 10))
    p9 = Process(target=test_encrypt, args=("test_3_OFB", key_256, sizes, 'OFB', iv, 80, 10))

    p1.start()
    p2.start()
    p3.start()
    p4.start()
    p5.start()
    p6.start()
    p7.start()
    p8.start()
    p9.start()

    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()
    p7.join()
    p8.join()
    p9.join()

    print("Done")
