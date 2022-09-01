from PyAES.AES import ofb_dec, ofb_enc

def run(val):
    key = "0" * 32
    iv = "0" * 32
    file_path = r"/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Visual-for-report/body.bin"

    if val == 1:
        ofb_enc(key, file_path, iv)
    elif val == 2:
        ofb_dec(key, f"{file_path}.enc", iv)

if __name__ == "__main__":
    run(1)
