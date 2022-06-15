def gen_table(data):
    matrix = [[0] * 16 for x in range(16)]
    #Generate the 16x16 input matrix (used)
    row = 15 
    col = 15
    print(data)
    print(len(data))
    print(matrix)
    print(len(matrix))
    for x in range(255, -1, -1):
        print(row, col)
        matrix[15-row][15-col] = data[((15-row)*(15-col))]
        if x % 16 ==0:
            col -= 1
    row = (row -1) % 16
    return matrix


#S-box substitution (used)
def sbox(bIn):
    SubBytesBox = gen_table(self.subBytesTable)
    col = bIn & 0xF
    row = (bIn >> 4) & 0xF
    return SubBytesBox[row][col]


#Inverse S-box substitution
def invsbox(bIn):
    invSubBytesBox = gen_table(self.invSubBytesTable)
    col = bIn & 0xF
    row = (bIn >> 4) & 0xF
    return invSubBytesBox[row][col]


#Perform the byte substitution layer (used)
def byte_sub(matrix):
    for r in range(4):
        for c in range(4):
            t = matrix[r][c]
            matrix[r][c] = sbox(matrix[r][c])
    return matrix


#Perform the inverse byte substitution layer
def inv_byte_sub(matrix):
    for r in range(4):
        for c in range(4):
            t = matrix[r][c]
            matrix[r][c] = invsbox(matrix[r][c])
    return matrix