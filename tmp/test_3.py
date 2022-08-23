from PyAES.AES import ofb_dec, ofb_enc

def run(val):
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    iv = "000102030405060708090a0b0c0d0e0f"
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/data.txt"

    if val == 1:
        ofb_enc(key, file_path, iv)
    elif val == 2:
        ofb_dec(key, f"{file_path}.enc", iv)

if __name__ == "__main__":
    run(2)
    print("Done!")
