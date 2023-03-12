# AES-128-ECB, AES-192-ECB and AES-256-ECB implementation
import time
from matrix_multiplications import mixColumnsMultiplication

def rotWord(word, startfrom):
    """
    Takes a list and an index and rotates the list to start from that index
    """
    result = word[startfrom:]
    result.extend(word[0:startfrom])
    return result

def subWord(word, inv = False):
    """
    Takes a list of bytes and returns a new list with subsituted bytes based on the S-box or the inverse S-box
    """
    for i in range(0, len(word)):
        if inv: getInvSBox(int(word[i][0], 16), int(word[i][1], 16))
        else: word[i] = getSBox(int(word[i][0], 16), int(word[i][1], 16))
    return word

def rcon(num):
    table = {1: '01', 2: '02', 3: '04', 4: '08', 5: '10', 6: '20', 7: '40',
                8: '80', 9: '1B', 10: '36', 11: '6C', 12: 'D8', 13: 'AB', 14: '4D'}
    return [table[num], '00', '00', '00']

def generateKeys(key):
    """
    Generates the keys for all rounds of the encryption and decryption processes
    """
    if len(key) != 32 and len(key) != 48 and len(key) != 64:
        raise ValueError("The key length should be 128, 192 or 256 bits")
    else:
        # It uses the key length to determine the number of keys to generate based on the number of rounds.
        keys_num = {32: 11, 48: 13, 64: 15}.get(len(key))
    
    # Each key is divided into 4 bytes words
    k = [key[i:i+8] for i in range(0, len(key), 8)] # The initial key given to the encrypt function
    keys = []

    for round_num in range(1, keys_num):
        round_key = []
        last = subWord(rotWord(wordSplit(k[-1]), 1)) # Apply subWord, rotWord to the last word of the key.
        for i in range(len(k)): # No. of words in the key
            if i == 0: # If current word is the first word in the key
                last = xorList(last, rcon(round_num)) # XOR rcon(round number) to the last word of the key
            if (((round_num * 8) + i) - 4) % 8 == 0  and len(k) > 6: # Only in case of AES-256
                last = subWord(last)

            # XOR the current word of the key to the last word of the key and replace last with it for the next iteration
            last = xorList(last, wordSplit(k[i]))
            round_key.append(''.join(last))
        keys.append(''.join(round_key)[:32])
        k = round_key
    return keys

def wordSplit(word):
    """
    Splits a word into smaller 1 byte words
    """
    return [word[i:i+2] for i in range(0, len(word), 2)]

def getSBox(x, y):
    """
    Encryption S-Box
    """
    sbox = [
        ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe' ,'d7', 'ab', '76'],
        ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
        ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
        ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
        ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
        ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
        ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
        ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
        ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
        ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
        ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
        ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
        ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
        ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
        ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
        ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
    ]
    return sbox[x][y]

def getInvSBox(x, y):
    """
    Decryption S-Box
    """
    sbox = [
        ['52', '09', '6a', 'd5', '30', '36', 'a5', '38', 'bf', '40', 'a3', '9e', '81', 'f3', 'd7', 'fb'],
        ['7c', 'e3', '39', '82', '9b', '2f', 'ff', '87', '34', '8e', '43', '44', 'c4', 'de', 'e9', 'cb'],
        ['54', '7b', '94', '32', 'a6', 'c2', '23', '3d', 'ee', '4c', '95', '0b', '42', 'fa', 'c3', '4e'],
        ['08', '2e', 'a1', '66', '28', 'd9', '24', 'b2', '76', '5b', 'a2', '49', '6d', '8b', 'd1', '25'],
        ['72', 'f8', 'f6', '64', '86', '68', '98', '16', 'd4', 'a4', '5c', 'cc', '5d', '65', 'b6', '92'],
        ['6c', '70', '48', '50', 'fd', 'ed', 'b9', 'da', '5e', '15', '46', '57', 'a7', '8d', '9d', '84'],
        ['90', 'd8', 'ab', '00', '8c', 'bc', 'd3', '0a', 'f7', 'e4', '58', '05', 'b8', 'b3', '45', '06'],
        ['d0', '2c', '1e', '8f', 'ca', '3f', '0f', '02', 'c1', 'af', 'bd', '03', '01', '13', '8a', '6b'],
        ['3a', '91', '11', '41', '4f', '67', 'dc', 'ea', '97', 'f2', 'cf', 'ce', 'f0', 'b4', 'e6', '73'],
        ['96', 'ac', '74', '22', 'e7', 'ad', '35', '85', 'e2', 'f9', '37', 'e8', '1c', '75', 'df', '6e'],
        ['47', 'f1', '1a', '71', '1d', '29', 'c5', '89', '6f', 'b7', '62', '0e', 'aa', '18', 'be', '1b'],
        ['fc', '56', '3e', '4b', 'c6', 'd2', '79', '20', '9a', 'db', 'c0', 'fe', '78', 'cd', '5a', 'f4'],
        ['1f', 'dd', 'a8', '33', '88', '07', 'c7', '31', 'b1', '12', '10', '59', '27', '80', 'ec', '5f'],
        ['60', '51', '7f', 'a9', '19', 'b5', '4a', '0d', '2d', 'e5', '7a', '9f', '93', 'c9', '9c', 'ef'],
        ['a0', 'e0', '3b', '4d', 'ae', '2a', 'f5', 'b0', 'c8', 'eb', 'bb', '3c', '83', '53', '99', '61'],
        ['17', '2b', '04', '7e', 'ba', '77', 'd6', '26', 'e1', '69', '14', '63', '55', '21', '0c', '7d']
    ]
    return sbox[x][y]

def xor(a, b):
    result = ''
    for i in range(1, len(a) + 1):
        i = -i
        if a[i] == b[i]: result = "0" + result
        else: result = "1" + result
    return result

def xorList(a: list, b: list):
    result = []
    for i in range(len(a)):
        bin_result = xor(bin(int(a[i], 16))[2:].zfill(8), bin(int(b[i], 16))[2:].zfill(8))
        result.append(('0' + hex(int(bin_result, 2))[2:])[-2:])
    return result

def messageXOR(message, key):
    if len(message) < 128: message = '0' * (128 - len(message)) + message
    if len(key) < 128: key = '0' * (128 - len(key)) + key
    block = hex(int(xor(message, key), 2))[2:]
    if len(block) % 32 != 0: block = "0" * (32 - (len(block) % 32)) + block
    return block

def generateByteMatrix(hex_data):
    matrix = []
    x = []
    for i in range(0, len(hex_data), 2):
        hex_string = hex_data[i: i+2]
        x.append(hex_string)
        if len(x) == 4:
            matrix.append(x)
            x = []
    return matrix

def subBytes(bytes_matrix, inv = False):
    for column in range(len(bytes_matrix)):
        for row in range(len(bytes_matrix[column])):
            if inv:
                bytes_matrix[column][row] = getInvSBox(int(bytes_matrix[column][row][0], 16), int(bytes_matrix[column][row][1], 16))
            else: 
                bytes_matrix[column][row] = getSBox(int(bytes_matrix[column][row][0], 16), int(bytes_matrix[column][row][1], 16))
    return bytes_matrix

def shiftRows(bytes_matrix):
    rows = list(zip(*bytes_matrix))
    for row in range(len(rows)):
        rows[row] = rotWord(list(rows[row]), row)
    matrix = [list(row) for row in list(zip(*rows))]
    return matrix

def invShiftRows(bytes_matrix):
    rows = list(zip(*bytes_matrix))
    for row in range(len(rows)):
        rows[row] = rotWord(list(rows[row]), -row)
    matrix = [list(row) for row in list(zip(*rows))]
    return matrix

def mixColumns(bytes_matrix, inv = False):
    new_matrix = []
    if inv: transformation_matrix = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
    else: transformation_matrix = [[2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2]]
    for column in bytes_matrix:
        new_column = []
        for row in transformation_matrix:
            value = '00000000'
            for i in range(4):
                if row[i] == 1: value = xor(bin(int(column[i], 16))[2:].zfill(8), value)
                else: value = xor(mixColumnsMultiplication(row[i], column[i]), value)
            new_column.append(('0' + hex(int(value, 2))[2:])[-2:])
        new_matrix.append(new_column)
    return new_matrix

def encrypt(message, key):
    if len(message) % 32 != 0:
        length = 32 - (len(message) % 32)
        message += length * "0"

    rounds_num = {32: 10, 48: 12, 64: 14}.get(len(key))
    round_keys = generateKeys(key)
    initial_key = key[:32]

    encrypted = ''
    for z in range(0, len(message), 32):
        block = messageXOR(bin(int(message[z: z+32], 16))[2:], bin(int(initial_key, 16))[2:])
        # print('New itration: ', block)
        for i in range(rounds_num):
            matrix = generateByteMatrix(block)
            matrix = subBytes(matrix)
            matrix = shiftRows(matrix)
            if i != rounds_num - 1: matrix = mixColumns(matrix)
            block = ''
            for k in matrix:
                for j in k:
                    block += j
            block = hex(int(xor(bin(int(block, 16))[2:].zfill(128), bin(int(round_keys[i], 16))[2:].zfill(128)), 2))[2:]
            if len(block) < 32: block = "0" * (32 - len(block)) + block
        encrypted += block

    return encrypted

def decrypt(cipher, key):
    rounds_num = {32: 10, 48: 12, 64: 14}.get(len(key))
    round_keys = generateKeys(key)
    round_keys.reverse()
    round_keys.append(key[:32])
    initial_key = round_keys.pop(0)

    decrypted = ''
    for z in range(0, len(cipher), 32):
        block = messageXOR(bin(int(cipher[z: z+32], 16))[2:], bin(int(initial_key, 16))[2:])
        for i in range(rounds_num):
            matrix = generateByteMatrix(block)
            matrix = invShiftRows(matrix)
            matrix = subBytes(matrix, True)
            block = ''
            for k in matrix:
                for j in k:
                    block += j
            block = hex(int(xor(bin(int(block, 16))[2:].zfill(128), bin(int(round_keys[i], 16))[2:].zfill(128)), 2))[2:]
            if len(block) < 32: block = "0" * (32 - len(block)) + block
            matrix = generateByteMatrix(block)
            if i != rounds_num - 1: matrix = mixColumns(matrix, True)
            block = ''
            for k in matrix:
                for j in k:
                    block += j
        decrypted += block

    return decrypted