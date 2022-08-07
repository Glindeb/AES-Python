from Py_AES.encrypt import encrypt
from Py_AES.decrypt import decrypt


def main(i):
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    iv = "000102030405060708090a0b0c0d0e0f"
    running_mode = "PCBC"
    file_path = r"C:\Users\Gabriel\Documents\GitHub\AES-Python\tmp\test_files\data.txt"

    if i == "enc":
        encrypt(key, file_path, running_mode, iv)
    else:
        file_path += ".enc"
        decrypt(key, file_path, running_mode, iv)


if __name__ == '__main__':
    main("enc")
