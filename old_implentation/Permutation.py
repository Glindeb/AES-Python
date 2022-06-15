#Helper function for a leftward rotation of a matrix row
def l_rotate_row(rowNum, shiftCount, matrix):
    for x in range(shiftCount):
        temp_byte = matrix[rowNum][0]
        matrix[rowNum][0] = matrix[rowNum][1]
        matrix[rowNum][1] = matrix[rowNum][2]
        matrix[rowNum][2] = matrix[rowNum][3]
        matrix[rowNum][3] = temp_byte
    return matrix


#GF(2^8) multiplication using AES irreducible polynomial
def gf2mult(x, y):
    ret = 0
    for i in range(8):
        if (y & 1) != 0:
            ret = ret ^ x
        b = (x & 0x80)
        x = (x << 1) & 0xFF
        if b:
            x = x ^ 0x1B
        y = (y >> 1) & 0xFF
    return ret


#Matrix multiplication done in GF(2^8)
def mmult(matb):
    c = [
            None,
            None,
            None,
            None
        ]
    c[0] = gf2mult(2, matb[0]) ^ gf2mult(3, matb[1]) ^ matb[2] ^ matb[3]
    
    c[1] = matb[0] ^ gf2mult(2, matb[1]) ^ gf2mult(3, matb[2]) ^ matb[3]
    
    c[2] = matb[0] ^ matb[1] ^ gf2mult(2, matb[2]) ^ gf2mult(3, matb[3])

    c[3] = gf2mult(3, matb[0]) ^ matb[1] ^ matb[2] ^ gf2mult(2, matb[3])
    
    return c


#Shift rows operation
def shift_rows(matrix):
    l_rotate_row(1, 1, matrix)
    l_rotate_row(2, 2, matrix)
    l_rotate_row(3, 3, matrix)
    return matrix

#Mix columns operation
def mix(matrix):
    for c in range(4):
        col = [ 
                matrix[0][c],
                matrix[1][c],
                matrix[2][c],
                matrix[3][c]
        ]
        col = mmult(col)
        matrix[0][c] = col[0]
        matrix[1][c] = col[1]
        matrix[2][c] = col[2]
        matrix[3][c] = col[3]
    return matrix

