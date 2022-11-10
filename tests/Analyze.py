from PyAES.encrypt import encrypt
from time import perf_counter
from random import randint
from os import remove


def write_data(data, name_f):
    with open(name_f + '.txt', 'w') as f:
        for i in data:
            f.write(str(i) + '\n')


def setup(count):
        with open("test_speed.txt", 'wb') as f:
            for j in range(count):
                f.write(bytes([randint(0, 255)]))


def speed_test(count, key, mode, iv):
    setup(count)
    start = perf_counter()
    encrypt(key, "test_speed.txt", mode, iv=iv)
    end = perf_counter()
    remove("test_speed.txt.enc")
    return end - start


if __name__ == '__main__':
    # Run in parallel
    keys = ["2b7e151628aed2a6abf7158809cf4f3c",
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"]
    iv = "000102030405060708090a0b0c0d0e0f"
    file_size = 1000000
    runs = 25

    # Test time difference between 128, 192 and 256 bit keys
    data = []
    for i in keys:
        data_tmp = []
        for j in range(runs):
            test = speed_test(file_size, i, 'ECB', iv)
            data_tmp.append(test)
        data.append(sum(data_tmp)/len(data_tmp))
    write_data(data, 'keys_test')

    # Test time difference between ECB, CBC and OFB modes
    data = []
    data_tmp = []
    for i in range(runs):
        test = speed_test(file_size, keys[0], 'OFB', iv)
        data_tmp.append(test)
    data.append(sum(data_tmp)/len(data_tmp))
    data_tmp = []
    for i in range(runs):
        test = speed_test(file_size, keys[0], 'CBC', iv)
        data_tmp.append(test)
    data.append(sum(data_tmp)/len(data_tmp))
    data_tmp = []
    for i in range(runs):
        test = speed_test(file_size, keys[0], 'ECB', iv)
        data_tmp.append(test)
    data.append(sum(data_tmp)/len(data_tmp))
    write_data(data, 'modes_test')

    print("Completed")
