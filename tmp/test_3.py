import os
size = os.path.getsize('tmp/test_files/data.txt')

print(size)

with open(r"C:\Users\Gabriel\Documents\GitHub\AES-Python\tmp\test_files\data.txt", "rb") as data:
    storage = []
    for i in range(int(size/16)):

        tmp = data.read(16)

        storage.append(tmp)

    storage.append(data.read())

tmp = ["69", "c4", "e0", "d8", "6a", "7b", "04", "30", "d8", "cd", "b7", "80", "70", "b4", "c5", "5a"]
for i in range(16):
    tmp[i] = int(tmp[i], 16)
print(tmp)

print(storage)

# see this for how to use bytearrays in python to prevent uneccesary converstions...