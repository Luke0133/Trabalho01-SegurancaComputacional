from bitarray import bitarray

log_keys = {"key" : bitarray(), "p10_key": bitarray(), "leftShift": [], "subKeys" : []}
           # | key recieved     | 10-bit permutation   | left shift for each key             | subkeys (after each 8-bit permuted choice) 
log_sdes = {"text": bitarray, "IP" : bitarray(), "SW" : bitarray(), "IP-1" : bitarray()}
log_sdesF = [{"E/P" : bitarray(), "xorBitsKey": bitarray(), "S0" : bitarray(), "S1" : bitarray(), "P4" : bitarray(), "result" : bitarray()},
             {"E/P" : bitarray(), "xorBitsKey": bitarray(), "S0" : bitarray(), "S1" : bitarray(), "P4" : bitarray(), "result" : bitarray()}]

ROUNDS = 2
S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]


# Key generation functions
def generateKeys(key:bitarray):
    log_keys["key"] = key
    
    # P10 (10 bit-key permutation)  -- ABCDEFGHIJ (1 2 3 4 5 6 7 8 9 10) -> CEBGDJAIHF (3 5 2 7 4 10 1 9 8 6)
    p10_key = key[2:3] + key[4:5] + key[1:2] + key[6:7] + key[3:4] + key[9:10] + key[0:1] + key[8:9] + key[7:8] + key[5:6]
    log_keys["p10_key"] = p10_key
    
    subKeys = []
    shiftKey = p10_key
    for i in range(ROUNDS):
        # Cirular Left Shift (ABCDEFGHIJ -> BCDEAGHIJF)
        shiftKey = circular_left_shift(shiftKey, i)
        log_keys["leftShift"].append(shiftKey)

        # Permuted Choice (P8) ->  6 3 7 4 8 5 10 9
        p8_key = shiftKey[5:6] + shiftKey[2:3] + shiftKey[6:7] + shiftKey[3:4] + shiftKey[7:8] + shiftKey[4:5] + shiftKey[9:10] + shiftKey[8:9]
        subKeys.append(p8_key)
        log_keys["subKeys"].append(p8_key)
    
    return subKeys

def circular_left_shift(bits:bitarray, n:int):
    for i in range(n + 1):
        bits = bits[1:5] + bits[0:1] + bits[6:10] + bits[5:6]
    return bits        

# Encryption algorithm
# cryptMode 0 -> encrypt
# cryptMode 1 -> decrypt
def sdes(keyList:list,text:bitarray, cryptMode = 0):
    log_sdes["text"] = text
    subKeys = keyList.copy()
    if cryptMode == 1:
        subKeys.reverse()  # Only difference between encrypting and decrypting is the subKeys order

    # Initial Permutation
    ipText = initial_permutation(text)
    log_sdes["IP"] = ipText

    #Feistel Rounds
    feistelText = ipText.copy()
    for i in range(ROUNDS):
        feistelResult = feistel(feistelText, subKeys[i], i) # fk
        log_sdesF[i]["result"] = feistelResult.copy()
        
        if i != ROUNDS - 1:
            feistelText = switch(feistelResult)          # SW
            log_sdes["SW"] = feistelText.copy()

    # Initial Permutation Reverse
    ipTextReverse = initial_permutation(feistelResult,True)
    log_sdes["IP-1"] = ipTextReverse

    return ipTextReverse


def initial_permutation(bits:bitarray, inverse = False):
    # IP: ABCDEFGH -> BFCADHEG (2 6 3 1 4 8 5 7)
    if not inverse:  # IP
        return bits[1:2] + bits[5:6] + bits[2:3] + bits[0:1] + bits[3:4] + bits[7:8] + bits[4:5] + bits[6:7]

    # IP^-1: BFCADHEG -> ABCDEFGH (4 1 3 5 7 2 8 6)
    else: # IP^-1 (inverse function)
        return bits[3:4] + bits[0:1] + bits[2:3] + bits[4:5] + bits[6:7] + bits[1:2] + bits[7:8] + bits[5:6]     

# Round is used only for logging
def feistel(bitString:bitarray, subKey:bitarray, round): 
    left, right = bitString[:4], bitString[4:]    # Gets left and right parts of string 

    mappingResult = mapping(right, subKey, round)
    log_sdesF[round]["P4"] = mappingResult

    newLeft = left ^ mappingResult       # XOR between left part and result of mapping function
    
    result = newLeft + right
    return result

# mapping function (F) -- round is only used for logging
def mapping(bitString:bitarray, subKey:bitarray, round):
    #Expansion/permutation : ABCD (1234)-> DABCBCDA (41232341)
    bitsEP = bitString[3:4] + bitString[0:1] + bitString[1:2] + bitString[2:3] + bitString[1:2] + bitString[2:3] + bitString[3:4] + bitString[0:1]
    log_sdesF[round]["E/P"] = bitsEP

    xorBitsKey = bitsEP ^ subKey
    log_sdesF[round]["xorBitsKey"] = xorBitsKey

    # Gets row and column indexes for S0 box and stores the value as binary in resultS1
    rowS0 = int((xorBitsKey[0:1] + xorBitsKey[3:4]).to01(), 2)
    columnS0 = int((xorBitsKey[1:2] + xorBitsKey[2:3]).to01(), 2)
    resultS0 = bitarray(format(S0[rowS0][columnS0], '02b'))
    log_sdesF[round]["S0"] = resultS0

    # Gets row and column indexes for S1 box and stores the value as binary in resultS1
    rowS1 = int((xorBitsKey[4:5] + xorBitsKey[7:8]).to01(), 2)
    columnS1 = int((xorBitsKey[5:6] + xorBitsKey[6:7]).to01(), 2)
    resultS1 = bitarray(format(S1[rowS1][columnS1], '02b'))
    log_sdesF[round]["S1"] = resultS1

    # P4 (Permutation): ABCD (1234) -> BDCA (2431)
    # Let the indexes be: (1) resultS0[0:1]; (2) resultS0[1:2]; (3) resultS1[0:1]; (4) resultS1[1:2]
    p4_bits =  resultS0[1:2] + resultS1[1:2] + resultS1[0:1]  + resultS0[0:1]
    log_sdesF[round]["P4"] = p4_bits

    return p4_bits


# switch function (SW)
def switch(bitString:bitarray):
      newString = bitString[4:] + bitString[:4]
      return newString
'''
passos:
1- permutação inicial
ABCDEFGHIJ -> CEBGDJAIHF (3 5 2 7 4 10 1 9 8 6)
2- função f(k)
3- segunda permutação que troca as metades dos dados
4- função f(k) novamente
5- função que é o inverso da permutação inicial
'''
'''

1101
1234

41232341
1110 1011
1010 0100
0100 1111

[00][10] -> 3 = 11 
'''