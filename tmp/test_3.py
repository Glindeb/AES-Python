import os
size = os.path.getsize('tmp/test_files/data.txt')

print(size)

with open(r"C:\Users\Gabriel\Documents\GitHub\AES-Python\tmp\test_files\data.txt", "rb") as data:
    storage = []
    for i in range(int(size/16)):

        tmp = data.read(16)

        storage.append(tmp)

    storage.append(data.read())



print(storage)

