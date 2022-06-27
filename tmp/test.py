def xor_bytes(a, b):
        #   Returns a new byte array with the elements xor'ed.
        return bytes(i^j for i, j in zip(a, b))

f = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 0, 1, 2], [3, 4, 5, 6]]
b = [[9, 0, 1, 2], [5, 6, 7, 8], [1, 2, 3, 4], [3, 4, 5, 6]]

print(f)

f = xor_bytes(f, b)

print(f)