from PyAES import AES
from sys import argv


# ---------------
# Decryption function
# ---------------
def decrypt(key, file_path, running_mode, iv=None, terminal_size=80):

    # Input validation
    if file_path[-4:] != ".enc":
        raise Exception('File is not encrypted in known format')
    if (len(key) / 2) not in [16, 24, 32]:
        raise Exception('Key length is not valid')
    elif running_mode in ["CBC", "PCBC", "CFB", "OFB", "CTR", "GCM"]:
        if (len(iv) / 2) != 16 or iv is None:
            raise Exception('IV length is not valid')

    # Running mode selection
    if running_mode == "ECB":
        AES.ecb_dec(key, file_path, terminal_size)
    elif running_mode == "CBC" and iv is not None:
        AES.cbc_dec(key, file_path, iv, terminal_size)
    elif running_mode == "PCBC" and iv is not None:
        AES.pcbc_dec(key, file_path, iv, terminal_size)
    else:
        raise Exception("Running mode not supported")


if __name__ == "__main__":
    decrypt(key=argv[1], file_path=argv[2], running_mode=argv[3], iv=argv[4])
