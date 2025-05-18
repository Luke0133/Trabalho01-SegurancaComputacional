from bitarray import bitarray
from math import ceil
import time
from . import sdes_functions as sdes

BLOCK_SIZE = 8

log_ecb = {"text" : bitarray(), "blocks": [], "resultBlocks": [], "result" : bitarray()}
log_cbc = {"text" : bitarray(), "IV": bitarray(), "blocks": [], "resultBlocks": [], "result" : bitarray()}

# Only works with messages that are multiples of 8 -->  There's no padding
def generate_blocks(bitString:bitarray):
    blocks =[]
    numberOfBlocks = len(bitString)//BLOCK_SIZE       
       
    for i in range(numberOfBlocks):
        start = BLOCK_SIZE * i
        blocks.append(bitString[start : start + BLOCK_SIZE])
    
    return blocks

# Works with any type of message -->  There's no padding
def generate_blocks_padding(bitString:bitarray):
    blocks =[]
    bitLen = len(bitString)
    numberOfBlocks = ceil(bitLen/BLOCK_SIZE)                 # Rounds up the number of blocks needed for bitString
    paddingNumber = numberOfBlocks * BLOCK_SIZE - bitLen     # Gets the number of bits to pad last block with
    paddedBitString = bitString.copy()                              
    paddedBitString.extend('0' * paddingNumber)              # Padds remaining bits of bitString

    # Separates bitString for each block
    for i in range(numberOfBlocks):
        start = BLOCK_SIZE * i
        blocks.append(paddedBitString[start : start + BLOCK_SIZE])

    # Appends another block with the number of bits padded
    blocks.append(bitarray(format(paddingNumber, f'0{BLOCK_SIZE}b')))           # Appends padding block (will contain the number of bits padded)

    return blocks

# Reverts blocks back to a bitarray
def revert_blocks(blocks):
    resultBits = bitarray()
    for i in range(len(blocks)):
        resultBits += blocks[i]
    return resultBits

# Reverts blocks back to a bitarray removing padding
def revert_blocks_padding(blocks):
    resultBits = bitarray()
    nonPadLen = len(blocks) - 2 # Length of blocks that don't relate to padding

    for i in range(nonPadLen):
        resultBits += blocks[i]

    # Gets paddingNumber
    paddingNumber = int(blocks[-1].to01(), 2)

    resultBits += blocks[-2][: (BLOCK_SIZE - paddingNumber)] # Gets non-padded bits of the last block

    return resultBits

# EBC Operation Mode (transforms bitarray into block sequence)
# cryptMode 0 -> encrypt
# cryptMode 1 -> decrypt
def ecb_operation_mode(bitSeq:bitarray, subKeys, cryptMode:int, padding = False):
    log_ecb["text"] = bitSeq.copy()
    blocks = []
    if padding and cryptMode == 0:
        blocks = generate_blocks_padding(bitSeq)
    else:
        blocks = generate_blocks(bitSeq)

    log_ecb["blocks"] = blocks.copy()

    new_blocks = ecb(blocks, subKeys, cryptMode)

    log_ecb["resultBlocks"] = new_blocks.copy()

    result = bitarray()
    if padding and cryptMode == 1:
        result = revert_blocks_padding(new_blocks)
    else:
        result = revert_blocks(new_blocks)
    
    log_ecb["result"] = result
    return result

# ECB operation mode (enc and dec)
def ecb(blocks, subkeys, cryptMode = 0):
    result=[]
    numBlocks = len(blocks)

    for i in range(numBlocks):
        if cryptMode == 0: 
            result.append(sdes.sdes(subkeys,blocks[i].copy()))
        else:
            result.append(sdes.sdes(subkeys,blocks[i].copy(), 1))
    
    return result

# CBC Operation Mode (transforms bitarray into block sequence)
# cryptMode 0 -> encrypt
# cryptMode 1 -> decrypt
def cbc_operation_mode(bitSeq:bitarray, iVector:bitarray, subkeys, cryptMode:int, padding = False):
    log_cbc["text"] = bitSeq.copy()
    log_cbc["IV"] = iVector
    blocks = []
    if padding and cryptMode == 0:  # Only padd when encrypting
        blocks = generate_blocks_padding(bitSeq)
    else:
        blocks = generate_blocks(bitSeq)

    log_cbc["blocks"] = blocks.copy()
    
    new_blocks = []
    if cryptMode == 0:
        new_blocks = cbc_encrypt(blocks, iVector, subkeys)
    else:
        new_blocks = cbc_decrypt(blocks, iVector, subkeys)

    log_cbc["resultBlocks"] = new_blocks.copy()

    result = bitarray()
    if padding and cryptMode == 1:
        result = revert_blocks_padding(new_blocks)
    else:
        result = revert_blocks(new_blocks)
    
    log_cbc["result"] = result
    return result    

# CBC operation mode (enc)
def cbc_encrypt(messageBlocks, iVector:bitarray, subkeys):
    cipherBlocks = []
    numBlocks = len(messageBlocks)

    cipherBlocks.append(sdes.sdes(subkeys, messageBlocks[0].copy() ^ iVector))

    for i in range(1, numBlocks):
        cipherBlocks.append(sdes.sdes(subkeys, messageBlocks[i].copy() ^ cipherBlocks[i - 1]))
    
    return cipherBlocks

# CBC operation mode (dec)
def cbc_decrypt(cipherBlocks, iVector:bitarray, subkeys):
    result = []
    numBlocks = len(cipherBlocks)
    
    result.append(sdes.sdes(subkeys, cipherBlocks[0].copy(), 1) ^ iVector)

    for i in range(1, numBlocks): 
        result.append(sdes.sdes(subkeys, cipherBlocks[i].copy(), 1) ^ cipherBlocks[i - 1])
    
    return result




"""
def encrypt(plainBlock:bitarray, key):
    plainBlock.reverse()
    return plainBlock

def decrypt(plainBlock:bitarray, key):
    plainBlock.reverse()
    return plainBlock

msg = bitarray("11010111011011001011101011110000")
iVector = bitarray("01010101")
print(msg)
print("ECB -ENC\n")
start = time.perf_counter()
cript = ecb_operation_mode(msg,'key',0,True)
end = time.perf_counter()
elapsed_ms = (end - start) * 1000
print(f"Elapsed time: {elapsed_ms:.4f} ms")
print("ECB -DEC\n")
ecb_operation_mode(cript,'key',1,True)
print("CBC -ENC\n")
print(msg)
cript = cbc_operation_mode(msg,iVector,'key',0,True)
print("CBC -DEC\n")
cbc_operation_mode(cript,iVector,'key',1,True)

cipher = cbc_encrypt(msg,iVector, 1)
print(cipher.to01())
print(cbc_decrypt(cipher,iVector, 1).to01())


#11010111 01101100 10111010 11110000
#11101011 00110110 01011101 00001111


#11010111 01101100 10111010 11110000
#01000001 10110100 01110000 00000001
"""
