# Parts that are imported
import sys
import time
import os
import math
from BitVector import *
from os.path import exists

#------------------------------------
#   Program information m.m
#------------------------------------
print('-----------------------------------------------------')
print('-----------------------------------------------------')
print('Welcome and thanks for using this implemetation \nof the AES (Advanced Encryption Standard) in python \nAuthor: Gabriel Lindeblad\n2022-05-23')
print('-----------------------------------------------------')
print('-----------------------------------------------------')
print('        [#][#] Program iniziating... [#][#]           ')
print('-----------------------------------------------------')
print('-----------------------------------------------------')
time.sleep(0.5)


#------------------------------------
#   Definiton of Core class
#------------------------------------
class Core:
    def __init__(self):
        #   For progress bar (setup later)
        self.progress = 0
        self.total_progress = None

        #   Error count
        self.number_of_errors = 0

        #   File path
        self.file_path = None

        #   Key
        self.key = None
        self.keysize = None
        self.key_storage = None

        #   Round info
        self.num_rounds = None
        self.round_keys = None

        #   Running Mode
        self.running_mode = None

        #   AESS modulus
        self.AES_modulus = BitVector(bitstring='100011011')

        #   xtime ...?
        self.xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

        #   Sbox & inverse Sbox
        self.subBytesTable = (
                                99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
                                202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
                                183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
                                4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
                                9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
                                83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
                                208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
                                81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
                                205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
                                96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
                                224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
                                231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
                                186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
                                112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
                                225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
                                140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22
                                )

        self.invSubBytesTable = (
                                82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
                                124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
                                84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
                                8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
                                114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
                                108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
                                144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
                                208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
                                58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
                                150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
                                71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
                                252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
                                31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
                                96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
                                160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
                                23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
                                )

        #   r_con ?
        r_con = (
                0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
                0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
                0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
                )


    def progress_bar(self):
        percent = 100 * (float(self.progress) / float(self.total_progress))
        bar = '#' * int(percent) + '-' * (100 - int(percent))
        print(f"\r[{bar}] {percent:.2f}%", end="\r")


    def error_message(self, message):
        print('[Error ' + message + ']')
        self.number_of_errors += 1


    def xor_bytes(a, b):
        #   Returns a new byte array with the elements xor'ed.
        return bytes(i^j for i, j in zip(a, b))


    def bytes_to_matrix(text):
        #   Converts a 16-byte array into a 4x4 matrix.
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]


    def matrix_to_bytes(matrix):
    #   Converts a 4x4 matrix into a 16-byte array.
        return bytes(sum(matrix, []))

    
    #   Add round key function
    def add_round_key(self, data, round):
        key_matrix = self.matrix_gen(self.round_keys[round])
        for r in range(4):
            for c in range(4):
                data[r][c] ^= key_matrix[r][c]
        return data

    
    #   Sub bytes function
    def sub_bytes(self, data):
        #Performs the byte substitution layer
        for r in range(4):
            for c in range(4):
                data[r][c] = self.subBytesTable(data[r][c])
        return data
    

    #   Inverse sub bytes function
    def inv_sub_bytes(self, data):
        #Preforms the inverse byte substitution layer
        for r in range(4):
            for c in range(4):
                data[r][c] = self.invSubBytesTable(data[r][c])
        return data
    

    #   Shift rows function
    def shift_rows(self, data):
        data[0][1], data[1][1], data[2][1], data[3][1] = data[1][1], data[2][1], data[3][1], data[0][1]
        data[0][2], data[1][2], data[2][2], data[3][2] = data[2][2], data[3][2], data[0][2], data[1][2]
        data[0][3], data[1][3], data[2][3], data[3][3] = data[3][3], data[0][3], data[1][3], data[2][3]
        return data


    #   Inverse shift rows function
    def inv_shift_rows(self, data):
        data[0][1], data[1][1], data[2][1], data[3][1] = data[3][1], data[0][1], data[1][1], data[2][1]
        data[0][2], data[1][2], data[2][2], data[3][2] = data[2][2], data[3][2], data[0][2], data[1][2]
        data[0][3], data[1][3], data[2][3], data[3][3] = data[1][3], data[2][3], data[3][3], data[0][3]
        return data


    #   Mix colums function
    def mix_colums(self, data):


        def mix_single_column(data):
            # see Sec 4.1.2 in The Design of Rijndael
            t = data[0] ^ data[1] ^ data[2] ^ data[3]
            u = data[0]
            data[0] ^= t ^ self.xtime(data[0] ^ data[1])
            data[1] ^= t ^ self.xtime(data[1] ^ data[2])
            data[2] ^= t ^ self.xtime(data[2] ^ data[3])
            data[3] ^= t ^ self.xtime(data[3] ^ u)


        def mix(data):
            for i in range(4):
                mix_single_column(data[i])
            return data

        data = mix(data)
        return data


    def inv_mix_columns(self, data):

        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = self.xtime(self.xtime(data[i][0] ^ data[i][2]))
            v = self.xtime(self.xtime(data[i][1] ^ data[i][3]))
            data[i][0] ^= u
            data[i][1] ^= v
            data[i][2] ^= u
            data[i][3] ^= v

        self.mix_columns(data)
        return data

    
    #   Rounds function
    def rounds(self, data_pice):
        #------------------------------------
        #   Iniztial key addition
        #------------------------------------
        data_pice = self.add_round_key(data_pice, 0)

        #   Debugg
        print('After add round key:')
        print(data_pice)

        #------------------------------------
        #   Rounds (9, 11 or 13)
        #------------------------------------
        for i in range(self.num_rounds - 1):
            data_pice = self.sub_bytes(data_pice)

            #   Debugg
            print('After sub bytes:')
            print(data_pice)

            data_pice = self.shift_rows(data_pice)

            #   Debugg
            print('After shift rows:')
            print(data_pice)

            data_pice = self.mix_colums(data_pice)

            #   Debugg
            print('After mix colums:')
            print(data_pice)

            data_pice = self.add_round_key(data_pice, (i + 1))

            #   Debugg
            print('After add round key:')
            print(data_pice)

        #------------------------------------
        #   Final round
        #------------------------------------
        data_pice = self.sub_bytes(data_pice)

        #   Debugg
        print('After sub bytes:')
        print(data_pice)

        data_pice = self.shift_rows(data_pice)

        #   Debugg
        print('After shift rows:')
        print(data_pice)

        data_pice = self.add_round_key(data_pice, -1)

        #   Debugg
        print('After add round key:')
        print(data_pice)

        #------------------------------------
        #   Return data pice
        #------------------------------------
        return data_pice


    #   Write function
    def write_data(self, data, file):
        for i in range(4):
            for t in range(4):
                print('bytes data:')
                print(bytes(data[i][t]))
                print(data[i][t])
                file.write(bytes(data[i][t]))


#------------------------------------
#   Defenition of Settings Class
#------------------------------------
class Settings(Core):
    def __init__(self):
        super().__init__()


    def set_keysize(self):
        while self.keysize not in ['128', '192', '256']:
            self.keysize = input('What keysize? [128|192|256]: ')
            if self.keysize not in ['128', '192', '256']:
                self.error_message('incompatible keysize, it must be either 128, 192 or 256')
        print('Key size set as [' + self.keysize + ']')
        self.keysize = int(self.keysize)
    

    def set_running_mode(self):
        while self.running_mode not in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
            self.running_mode = input('What running mode? [ECB|CBC|CFB|OFB|CTR]: ')
            if self.running_mode not in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
                self.error_message('incompatible running mode, it must be either ECB, CBC, CFB, OFB or CTR')
        print('Mode set [' + self.running_mode + ']')


    def key_selection(self):
        key_s = None
        while key_s not in ['1', '2']:
            key_s = input('Key [Use new -> 1]|[Use existing -> 2]: ')
            if key_s not in ['1', '2']:
                self.error_message('incompatible awnser, it must be either 1 or 2')
        
        if key_s == '1':
        #key generation ('Y', 'N')
            key_g_mode = None
            while key_g_mode not in ['1', '2']:
                key_g_mode = input('What key input mode, [Text file -> 1]|[manual -> 2]: ')
                if key_g_mode not in ['1', '2']:
                    self.error_message('incompatible awnser, it must be either 1 or 2')
            
            if key_g_mode == '1':
                while True:
                    self.key_storage = input('Specify key path:')
                    if exists(self.key_storage):
                        break
                    self.error_message('File [' + self.key_storage + '] not found')
                print('Key path set as [' + self.key_storage + ']')
                with open(self.key_storage) as i:
                    key = i.readlines()
                    key = key.strip()
                    key += '0' * (self.keysize // 8 - len(key)) if len(key) < self.keysize // 8 else key[:self.keysize // 8]
                    self.key = BitVector(textstring=key)

            #Key storage mode
            if key_g_mode == '2':
                key = input("\nEnter key (any number of chars): ")
                key_temp = key.strip()
                key_temp += '0' * (self.keysize // 8 - len(key)) if len(key) < self.keysize // 8 else key[:self.keysize // 8]
                self.key = BitVector(textstring=key_temp)
                while self.key_storage not in ['Y', 'N']:
                    self.key_storage = input('Do you want to store the key or not? [store -> Y]|[do not store -> N]: ')
                    if self.key_storage not in ['Y', 'N']:
                        self.error_message('incompatible awnser, it must be either 1 or 2')
                if self.key_storage == 'Y':
                    while True:
                        self.key_storage = input('Specify key path (end with /): ')
                        if exists(self.key_storage):
                            FILEOUT = open((self.key_storage + 'secret.key'), 'wb')
                            BitVector(textstring=key).write_to_file(FILEOUT)
                            FILEOUT.close()
                            break
                        self.error_message('Location [' + self.key_storage + '] not found')
                    print('Key storage location set as [' + self.key_storage + ']')
    
        # specifie key path
        if key_s == '2':
            while True:
                self.key_storage = input('Specify key path: ')
                if exists(self.key_storage):
                    break
                self.error_message('File [' + self.key_storage + '] not found')
            print('Key path set as [' + self.key_storage + ']')
            with open(self.key_storage) as i:
                key = i.readlines()
                key = key.strip()
                key += '0' * (self.keysize // 8 - len(key)) if len(key) < self.keysize // 8 else key[:self.keysize // 8]
                self.key = BitVector(textstring=key)
        print('Key selection process complete')


#------------------------------------
#   Definiton of Key expantion class
#------------------------------------
class KeyExpantion(Core):
    def __init__(self):
        super().__init__()


    #Key expantion core function
    def Key_expand(self):
        key_words = []
        key_bv = self.key

        if self.keysize == 128:
            key_words = self.gen_key_schedule_128(key_bv)
        elif self.keysize == 192:
            key_words = self.gen_key_schedule_192(key_bv)
        elif self.keysize == 256:
            key_words = self.gen_key_schedule_256(key_bv)

        if self.keysize == 128:
            self.num_rounds = 10
        if self.keysize == 192:
            self.num_rounds = 12
        if self.keysize == 256:
            self.num_rounds = 14

        self.round_keys = [None for i in range(self.num_rounds + 1)]
        for i in range(self.num_rounds + 1):

            self.round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3]).get_bitvector_in_hex()
            self.round_keys[i] = [int(('0x' + self.round_keys[i][t:t+2]), 16) for t in range(0, len(self.round_keys[i]), 2)]

        #   Debugg
        print(key_words)
        print(self.round_keys)


    def gee(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size=0)
        for i in range(4):
            newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), self.AES_modulus, 8)
        return newword, round_constant


    #Key expantion for 128bit key
    def gen_key_schedule_128(self, key_bv):
        key_words = [None for i in range(44)]
        round_constant = BitVector(intVal=0x01, size=8)
        for i in range(4):
            key_words[i] = key_bv[i * 32: i * 32 + 32]
        for i in range(4, 44):
            if i % 4 == 0:
                kwd, round_constant = self.gee(key_words[i - 1], round_constant, self.subBytesTable)
                key_words[i] = key_words[i - 4] ^ kwd
            else:
                key_words[i] = key_words[i - 4] ^ key_words[i - 1]
        return key_words


    #Key expantion for 192bit key
    def gen_key_schedule_192(self, key_bv):
        key_words = [None for i in range(52)]
        round_constant = BitVector(intVal=0x01, size=8)
        for i in range(6):
            key_words[i] = key_bv[i * 32: i * 32 + 32]
        for i in range(6, 52):
            if i % 6 == 0:
                kwd, round_constant = self.gee(key_words[i - 1], round_constant, self.subBytesTable)
                key_words[i] = key_words[i - 6] ^ kwd
            else:
                key_words[i] = key_words[i - 6] ^ key_words[i - 1]
        return key_words


    #Key expantion for 256 bit key
    def gen_key_schedule_256(self, key_bv):
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal=0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i * 32: i * 32 + 32]
        for i in range(8, 60):
            if i % 8 == 0:
                kwd, round_constant = self.gee(key_words[i - 1], round_constant, self.subBytesTable)
                key_words[i] = key_words[i - 8] ^ kwd
            elif (i - (i // 8) * 8) < 4:
                key_words[i] = key_words[i - 8] ^ key_words[i - 1]
            elif (i - (i // 8) * 8) == 4:
                key_words[i] = BitVector(size=0)
                for j in range(4):
                    key_words[i] += BitVector(intVal=self.subBytesTable[key_words[i - 1][8 * j:8 * j + 8].intValue()], size=8)
                key_words[i] ^= key_words[i - 8]
            elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
                key_words[i] = key_words[i - 8] ^ key_words[i - 1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words


#------------------------------------
#   Definiton of Encryption class
#------------------------------------
class Encrypt(Settings, KeyExpantion):
    def __init__(self):
        super().__init__()


    def encrypt(self):
        #------------------------------------
        #   File selection
        #------------------------------------
        #self.file_path = input('Enter path to file to encrypt: ')
        self.file_path = 'test.txt'

        #------------------------------------
        #   Key and options selection
        #------------------------------------

        # Keysize option (128, 192, 256)
        # self.set_keysize()
        self.keysize = 128

        # Modes of omperation ('ECB', 'CBC', 'CFB', 'OFB', 'CTR')
        # self.set_running_mode()
        self.running_mode = 'ECB'

        # Use existing key or generate one
        # self.key_selection()
        self.key = BitVector(textstring=b'000102030405060708090a0b0c0d0e0f')
        print('Key used:')
        print(self.key)

        # Expanding key into round keys based on options
        self.Key_expand()

        if self.running_mode == 'ECB':
            self.ECB()
        elif self.running_mode == 'CBC':
            print('\r')
            #self.CBC()
        elif self.running_mode == 'CFB':
            print('\r')
            #self.CFB()
        elif self.running_mode == 'OFB':
            print('\r')
            #self.OFB()
        elif self.running_mode == 'CTR':
            print('\r')
            #self.CTR()
    

    def ECB(self):
        self.total_progress = os.stat(self.file_path).st_size
        FILEOUT = open((self.file_path + '.locked'), 'wb')
        print()
        self.progress_bar()


        with open(self.file_path, 'rb') as compute_data:
            #------------------------------------
            #   First data chunk
            #------------------------------------
            if self.total_progress > 16:
                compute_data_pice = self.matrix_gen([int.from_bytes(compute_data.read(1), 'big') for i in range(16)])

                #   Debugg
                print('compute_data_pice:')
                print(compute_data_pice)

                compute_data_pice = self.rounds(compute_data_pice)
                self.write_data(compute_data_pice, FILEOUT)

                self.progress += 16
                self.progress_bar()

            #------------------------------------
            #   Data cunks
            #------------------------------------
            if self.total_progress > 32:
                for i in range(math.floor(self.total_progress / 16) - 1):
                    compute_data_pice = self.matrix_gen([int.from_bytes(compute_data.read(1), 'big') for i in range(16)])
                    
                    #   Debugg
                    print('compute_data_pice:')
                    print(compute_data_pice)

                    compute_data_pice = self.rounds(compute_data_pice)
                    self.write_data(compute_data_pice, FILEOUT)

                    self.progress += 16
                    self.progress_bar()

            #------------------------------------
            #   Final data chunk
            #------------------------------------
            lengh_need = 16 - self.total_progress + self.progress
            compute_data_pice = [[int.from_bytes(compute_data.read(1), 'big') for i in range(self.total_progress - self.progress)]]
            
            #   Debugg
            print('compute_data_pice:')
            print(compute_data_pice)

            #   Padding last data pice if needed (need to be fixed)
            if lengh_need > 0:
                for i in range(lengh_need):
                    compute_data_pice.append(0)
            compute_data_pice = self.matrix_gen(compute_data_pice)

            compute_data_pice = self.rounds(compute_data_pice)
            self.write_data(compute_data_pice, FILEOUT)

            self.progress += 16 - lengh_need
            self.progress_bar()
            print('\n')
    
        FILEOUT.close()       


e = Encrypt()
e.encrypt()