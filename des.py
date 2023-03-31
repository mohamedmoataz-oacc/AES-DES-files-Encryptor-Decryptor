def getPC(block, permutation):
    new_block = ""
    for i in range(8):
        for j in range(len(permutation[i])):
            new_block += block[permutation[i][j] - 1]
    return new_block

def createBlockPairs(kp):
    index = len(kp) // 2
    c_now, d_now = kp[:index], kp[index:]
    shifting = "1122222212222221"
    pairs = []
    
    for i in range(16):
        shifts = int(shifting[i])
        first = c_now[:shifts]
        c_now = c_now[shifts:] + first
        first = d_now[:shifts]
        d_now = d_now[shifts:] + first
        pairs.append(c_now + d_now)
    
    return pairs

permutation1 = [
    [57, 49, 41, 33, 25, 17, 9], [1, 58, 50, 42, 34, 26, 18], [10, 2, 59, 51, 43, 35, 27], [19, 11, 3, 60, 52, 44, 36],
    [63, 55, 47, 39, 31, 23, 15], [7, 62, 54, 46, 38, 30, 22], [14, 6, 61, 53, 45, 37, 29], [21, 13, 5, 28, 20, 12, 4]
]
permutation2 = [
    [14, 17, 11, 24, 1, 5], [3, 28, 15, 6, 21, 10], [23, 19, 12, 4, 26, 8], [16, 7, 27, 20, 13, 2],
    [41, 52, 31, 37, 47, 55], [30, 40, 51, 45, 33, 48], [44, 49, 39, 56, 34, 53], [46, 42, 50, 36, 29, 32]
]
def generateKeys(key):
    if len(key) % 64 != 0:
        raise ValueError("The key length in hexadecimal should be a multiple of 16")
    key_plus = getPC(key, permutation1)
    keys = createBlockPairs(key_plus)
    
    new_keys = []
    for i in keys:
        new_keys.append(getPC(i, permutation2) )
    return new_keys

e_bit = [
    [32, 1, 2, 3, 4, 5], [4, 5, 6, 7, 8, 9], [8, 9, 10, 11, 12, 13], [12, 13, 14, 15, 16, 17],
    [16, 17, 18, 19, 20, 21], [20, 21, 22, 23, 24, 25], [24, 25, 26, 27, 28, 29], [28, 29, 30, 31, 32, 1]
]
def mysteriousFunctionF(r, k):
    r = getPC(r, e_bit)
    k_xor_Er = bin(int(r, 2) ^ int(k, 2))[2:].zfill(len(r))

    six_bits_groups = [k_xor_Er[i:i+6] for i in range(0, len(k_xor_Er), 6)]

    four_bits_groups = ""
    for i in range(8):
        four_bits_groups += anotherFunctionForSBox(six_bits_groups[i], i + 1)

    permutation = [[16, 7, 20, 21], [29, 12, 28, 17], [1, 15, 23, 26], [5, 18, 31, 10], [2, 8, 24, 14], [32, 27, 3, 9], [19, 13, 30, 6], [22, 11, 4, 25]]
    return getPC(four_bits_groups, permutation)
    
def anotherFunctionForSBox(six_bits_block, number):
    s_box = getSBox(number)
    row, column = six_bits_block[0] + six_bits_block[-1], six_bits_block[1:-1]
    row, column = int(row, 2), int(column, 2)
    output = bin(s_box[row][column])[2:][-4:].zfill(4)
    return output

boxes = {
    '1': [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    '2': [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    '3': [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    '4': [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    '5': [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    '6': [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    '7': [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    '8': [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
}
def getSBox(number):
    return boxes[str(number)]

permutation0 = [
    [58, 50, 42, 34, 26, 18, 10, 2], [60, 52, 44, 36, 28, 20, 12, 4], [62, 54, 46, 38, 30, 22, 14, 6],
    [64, 56, 48, 40, 32, 24, 16, 8], [57, 49, 41, 33, 25, 17, 9, 1], [59, 51, 43, 35, 27, 19, 11, 3],
    [61, 53, 45, 37, 29, 21, 13, 5], [63, 55, 47, 39, 31, 23, 15, 7]
]
final_permutation = [
    [40, 8, 48, 16, 56, 24, 64, 32],
    [39, 7, 47, 15, 55, 23, 63, 31],
    [38, 6, 46, 14, 54, 22, 62, 30],
    [37, 5, 45, 13, 53, 21, 61, 29],
    [36, 4, 44, 12, 52, 20, 60, 28],
    [35, 3, 43, 11, 51, 19, 59, 27],
    [34, 2, 42, 10, 50, 18, 58, 26],
    [33, 1, 41, 9, 49, 17, 57, 25]
]
def applayDES(message, keys):
    m_plus = getPC(message, permutation0)

    index = len(m_plus) // 2
    iterations_return = ""

    l_now = m_plus[:index]
    r_now = m_plus[index:]
    for i in range(16):
        l = r_now
        r = bin(int(l_now, 2) ^ int(mysteriousFunctionF(r_now, keys[i]), 2))[2:].zfill(len(l_now))
        iterations_return = r + l
        l_now = l
        r_now = r

    return hex(int(getPC(iterations_return, final_permutation), 2))[2:].zfill(16)

def encrypt(message, key):
    if len(message) % 16 != 0:
        length = 16 - (len(message) % 16)
        message += length * "0"

    blocks = []
    for i in range(0, len(message), 16):
        blocks.append(message[i: i + 16])
    
    keys = generateKeys(bin(int(key, 16))[2:].zfill(64))
    ciphered_blocks = []
    for block in blocks:
        block_cipher = applayDES(bin(int(block, 16))[2:].zfill(64), keys)
        ciphered_blocks.append(block_cipher)
    hex_cipher = "".join(ciphered_blocks)
    return hex_cipher

def decrypt(cipher, key):
    blocks = []
    for i in range(0, len(cipher), 16):
        blocks.append(cipher[i: i + 16])
    
    keys = generateKeys(bin(int(key, 16))[2:].zfill(64))
    keys.reverse()
    deciphered_blocks = []
    for block in blocks:
        block_cipher = applayDES(bin(int(block, 16))[2:].zfill(64), keys)
        deciphered_blocks.append(block_cipher)
    hex_message = "".join(deciphered_blocks)
    return hex_message