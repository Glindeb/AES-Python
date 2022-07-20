import AES_Module.AES as AES

def enc():
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    running_mode = "ECB"
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/body.bin"

    AES.encrypt(key, file_path, running_mode)

def dec():
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    running_mode = "ECB"
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/body.bin.enc"

    AES.decrypt(key, file_path, running_mode)

if __name__ == '__main__':
    enc()

