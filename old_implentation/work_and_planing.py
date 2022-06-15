from BitVector import *

#------------------------------------------------------------
# File import and read tests (Done)
#------------------------------------------------------------
# filename = '/Users/gabriellindeblad/Documents/GitHub/AES-Test-Python/test.txt'
filename = 'test.txt'

# opens an existing file and reads the first bits in to a variable
with open(filename, 'rb') as bit:
    bv1 = [i for i in bit.read(16)]
    print(bv1)
    print(type(bv1))
    print(len(bv1))
    print()
    l1 = bv1
    bit.close()

# a way to create and write somthing i nits to a new file
with open('test.txt', 'wb') as file:
    file.write(l1)
    file.close()

# a way to add bits to the end of alredy existing file (continue writing in a file)
with open('test.txt', 'ab') as i:
    i.write(b'\xcds\xc7>')
    i.close()

# opens and reads the contents for a file in bits in to a variable
with open('test.txt', 'rb') as file:
    print(file.read())
    print(type(file.read()))
    print('--------------------------------------')
    print('--------------------------------------')
    file.close()

with open('test.txt', 'rb') as t:
    tmp4 = []
    for i in t.read():
        print(i)
        print(type(i))
        tmp4.append(i)
        print(tmp4)
        print()

print(tmp4[1])
print(tmp4[2])

tmp3 = tmp4[1] ^ tmp4[2]
print(tmp3)
print(type(tmp3))

tmp3 = hex(tmp3)
print(tmp3)
print(type(tmp3))
print('--------------------------------------')
print('--------------------------------------')


#------------------------------------------------------------
# Matreix generation function (Done)
#------------------------------------------------------------
def matrix_gen(data):
    matrix = [[data[a+(4*b)] for a in range(4)] for b in range(4)]
    return matrix


#------------------------------------------------------------
# Key expantion function (Done)
#------------------------------------------------------------
# See core file!!!


#------------------------------------------------------------
# Add round key function (In Progress)
#------------------------------------------------------------
# Add round key operation
def add_round_key(r_key, matrix):
    key_matrix = matrix_gen(r_key[0])
    for r in range(4):
        for c in range(4):
            matrix[r][c] = matrix[r][c] ^ key_matrix[r][c]
    return matrix


#------------------------------------------------------------
# Permutation functions (In Progress)
#------------------------------------------------------------
# See Permutation file!!!
# hopefully done and working but must test with the rest and adapt so it gets the right
# input and that the output is used corectly.


#------------------------------------------------------------
# Sbox generation functions (Done)
#------------------------------------------------------------
# See Core file!!!


#------------------------------------------------------------
# Byte substitution functions (In Progress)
#------------------------------------------------------------
# See sub bytes file!!!
# Check the function and adapt to the full main function in a corect way.


#------------------------------------------------------------
# File import function and core loop test (In Progress)
#------------------------------------------------------------
# data, running_mode, key, keysize, key_g_mode, key_storage
print('--------------------------------------')
print('--------------------------------------')
print()


def encrypt(file_path):
    with open(file_path, 'rb') as compute_data:
        while True:
            compute_data_pice = matrix_gen([hex(i) for i in compute_data.read(16)])
            print(compute_data_pice)
            break

encrypt(file_path='secret.key')


print()
print('--------------------------------------')
print('--------------------------------------')

#------------------------------------------------------------
# Core function structure and implementation (In Progress)
#------------------------------------------------------------
# See core file!!!
# Put together the core function pice by pice to form the ECB to a begeing and then
# later implement the other types of running modes.
