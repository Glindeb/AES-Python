def shift_rows(data):
        data[0][1], data[1][1], data[2][1], data[3][1] = data[1][1], data[2][1], data[3][1], data[0][1]
        data[0][2], data[1][2], data[2][2], data[3][2] = data[2][2], data[3][2], data[0][2], data[1][2]
        data[0][3], data[1][3], data[2][3], data[3][3] = data[3][3], data[0][3], data[1][3], data[2][3]
        return data



print(shift_rows([[0x63, 0x7c, 0x77, 0x7b], [0xf2, 0x6b, 0x6f, 0xc5], [0x30, 0x01, 0x67, 0x2b], [0xfe, 0xd7, 0xab, 0x76]]))