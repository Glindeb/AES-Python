import AES_Module.AES as AES


def main(i):
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    iv = "000102030405060708090a0b0c0d0e0f"
    running_mode = "CBC"
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/data.txt"

    if i == "enc":
        AES.encrypt(key, file_path, running_mode, iv)
    else:
        file_path += ".enc"
        AES.decrypt(key, file_path, running_mode, iv)


if __name__ == '__main__':
    main("dec")
