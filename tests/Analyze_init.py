from random import randint
from time import sleep
from os import remove

name = 'T-'
end = 'B.txt'

def setup(count):
    for i in range(count):
        i = (8 * i) + 8
        with open(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + str(i) + end, 'wb') as f:
            for j in range(i):
                f.write(bytes([randint(0, 255)]))

def clean(count):
    for i in range(count):
        i = (8 * i) + 8
        remove(r'/Users/gabriellindeblad/Documents/GitHub/AES-Python/tests/test_data/Test_setup_analyze/' + name + str(i) + end)

if __name__ == '__main__':
    setup(20)
    sleep(10)
    clean(20)

