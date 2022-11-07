from PyAES.encrypt import encrypt
from PyAES.decrypt import decrypt


def main(i):
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    iv = "000102030405060708090a0b0c0d0e0f"
    running_mode = "ECB"
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/sword_fifth_bakground_light_1.jpg"

    if i == "enc":
        encrypt(key, file_path, running_mode)
    else:
        file_path += ".enc"
        decrypt(key, file_path, running_mode)


if __name__ == '__main__':
    main("enc")