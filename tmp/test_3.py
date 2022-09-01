from PyAES.AES import ecb_dec, ecb_enc

def run(val):
    key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = "000102030405060708090a0b0c0d0e0f"
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/sword_fifth_bakground_light_1.jpg"

    if val == 1:
        ecb_enc(key, file_path)
    elif val == 2:
        ecb_dec(key, f"{file_path}.enc")

if __name__ == "__main__":
    run(1)
