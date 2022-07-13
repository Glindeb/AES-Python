# nk = number of colums, nr = number of rounds
def Key_schedule(key, nk, nr):
    # Create list and populates first nk words with key
    words = [(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]) for i in range(nk)]

    # fill out the rest based on previews words, rotword, subword and rcon values
    limit = False
    for i in range(nk, (nr * nk)):
        # get required previous keywords
        temp, word = words[i-1], words[i-4]

        # if multiple of nk use rot, sub, rcon etc
        if i % nk == 0:
            x = SubWord(RotWord(temp))
            rcon = round_constant[int(i/nk)]
            temp = hexor(x, hex(rcon)[2:])
            limit = False
        elif i % 4 == 0:
            limit = True

        if i % 4 == 0 and limit and nk > 8:
            temp = SubWord(temp)

        # creating strings of hex rather than tuple
        word = ''.join(word)
        temp = ''.join(temp)

        # xor the two hex values
        xord = hexor(word, temp)
        words.append((xord[:2], xord[2:4], xord[4:6], xord[6:8]))
    return words


def Keyschedule_256bit(key):
    # prep word list to hold 60 tuples
    words = [()]*60

    # fill out first 8 words based on the key
    for i in range(8):
        words[i] = (key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])

    # fill out the rest based on previews words, rotword, subword and rcon values
    limit = False
    for i in range(8, 60):
        # get required previous keywords
        temp = words[i-1]
        word = words[i-8]

        # if multiple of 4 use rot, sub, rcon etc
        if i % 8 == 0:
            print("f")
            x = RotWord(temp)
            y = SubWord(x)
            rcon = round_constant[int(i/8)]
            temp = hexor(y, hex(rcon)[2:])
            limit = False
        elif i % 4:
            limit = True

        if i % 4 == 0 and limit:
            print("g")
            temp = SubWord(temp)

        # creating strings of hex rather than tuple
        word = ''.join(word)
        temp = ''.join(temp)

        # xor the two hex values
        xord = hexor(word, temp)
        words[i] = (xord[:2], xord[2:4], xord[4:6], xord[6:8])
    return words