import os
import time
from bitarray import bitarray
from . import sdes_functions as sdes
from . import operation_modes as op

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_binary_string(s):
    for char in s:
        if char not in '01':
            return False
    return True

def main_ui():
    while True:
        clear_screen()
        print("S-DES -- Developed by Eduardo Pereira and Luca Megiorin")
        print("Choose an option:\n| 1. S-DES\n| 2. Operation Modes\n| 3. Exit")
        try:
            choice = int(input("Type the number to select your answer: "))
            if choice in [1, 2, 3]:
                return choice
        except ValueError:
            pass

def sdes_ui():
    while True:
        while True:
            clear_screen()
            print("S-DES: Encryption and Decryption Mode")
            print("Choose an option:\n| 1. Use Project Data\n| 2. Type Custom Data\n| 3. Return")
            try:
                choice = int(input("Type the number to select your answer: "))
                if choice in [1, 2, 3]:
                    break
            except ValueError:
                pass

        match choice:
            case 1:
                clear_screen()
                print("S-DES: Encryption and Decryption Mode - Project Data")
                print("| Key: 1010000010")
                print("| Plaintext: 11010111\n")

                key = bitarray("1010000010")
                plaintext = bitarray("11010111")
                        
                start = time.perf_counter()
                subKeys = sdes.generateKeys(key)
                end = time.perf_counter()
                key_results_ui(sdes.log_keys, (end - start) * 1000)
                
                start = time.perf_counter()
                ciphertext = sdes.sdes(subKeys,plaintext)
                end = time.perf_counter()
                sdes_enc_results_ui(sdes.log_sdes,sdes.log_sdesF, (end - start) * 1000)

                start = time.perf_counter()
                sdes.sdes(subKeys,ciphertext,1)
                end = time.perf_counter()
                sdes_dec_results_ui(sdes.log_sdes,sdes.log_sdesF, (end - start) * 1000)

                input("Press any key to continue")
            case 2: 
                while True:
                    clear_screen()
                    print("S-DES: Encryption and Decryption Mode - Custom Data")
                    try:
                        inputString = input("Enter 10-bit key: ") 
                        if len(inputString) == 10 and is_binary_string(inputString):
                            key = bitarray(inputString)
                            break
                    except ValueError:
                        pass
                
                while True:
                    clear_screen()
                    print("S-DES: Encryption and Decryption Mode - Custom Data")
                    print(f"Enter 10-bit key: {key.to01()}")
                    try:
                        inputString = input("Type an 8-bit text: ")
                        if len(inputString) == 8 and is_binary_string(inputString):
                            plaintext = bitarray(inputString)
                            break
                    except ValueError:
                        pass
                
                clear_screen()
                print("S-DES: Encryption and Decryption Mode - Custom Data")
                print(f"| Key: {key.to01()}")
                print(f"| Plaintext: {plaintext.to01()}\n")
                        
                start = time.perf_counter()
                subKeys = sdes.generateKeys(key)
                end = time.perf_counter()
                key_results_ui(sdes.log_keys, (end - start) * 1000)
                
                start = time.perf_counter()
                ciphertext = sdes.sdes(subKeys,plaintext)
                end = time.perf_counter()
                sdes_enc_results_ui(sdes.log_sdes,sdes.log_sdesF, (end - start) * 1000)

                start = time.perf_counter()
                sdes.sdes(subKeys,ciphertext,1)
                end = time.perf_counter()
                sdes_dec_results_ui(sdes.log_sdes,sdes.log_sdesF, (end - start) * 1000)

                input("Press any key to continue")

            case 3:
                return
            case _: # Error
                return
                
def key_results_ui(log: dict, time_elapsed):    
    print("Generating Sub-Keys:")
    
    print(f"> Key Used:  {log['key'].to01()}")
    print(f"> 10-Bit Permutation (P10):  {log['p10_key'].to01()}")
    print(f"> Circular Left Shift (LS-1):  {log['leftShift'][0].to01()}")
    print(f"> Permuted choice 1 (P8):  {log['subKeys'][0].to01()}")
    print(f"> Double Circular Left Shift (LS-2):  {log['leftShift'][1].to01()}")
    print(f"> Permuted choice 2 (P8):  {log['subKeys'][1].to01()}")
    print(f"> Sub-Keys Generated:  {log['subKeys'][0].to01()}, {log['subKeys'][1].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")

def sdes_enc_results_ui(log: dict, logF: dict, time_elapsed):  
    print("Encrypting Plaintext:")
    print(f"> Plaintext Used:  {log['text']}")

    print(f"> Initial Permutation:  {log['IP']}")
    print(f"> Feistel Round 1: Left = {log['IP'][:4].to01()},  Right = {log['IP'][4:].to01()}")
    print(f"  >> Expansion/Permutation (E/P):  {logF[0]['E/P'].to01()}")
    print(f"  >> XOR with SubKey (Right XOR K1):  {logF[0]['xorBitsKey'].to01()}")
    print(f"  >> S-Boxes:  S0 = {logF[0]['S0'].to01()}, S1 = {logF[0]['S0'].to01()}")
    print(f"  >> 4-Bit Permutation (P4):  {logF[0]['P4'].to01()}")
    print(f"  >> XOR with Left (Left XOR P4):  {logF[0]['result'][:4].to01()}")
    print(f"  >> Result (XOR with Left || Right):  {logF[0]['result'].to01()}")
    print(f"> Switch Function (SW):  {log['SW'].to01()}")
    print(f"> Feistel Round 2: Left = {log['SW'][:4].to01()},  Right = {log['SW'][4:].to01()}")
    print(f"  >> Expansion/Permutation (E/P):  {logF[1]['E/P'].to01()}")
    print(f"  >> XOR with SubKey (Right XOR K1):  {logF[1]['xorBitsKey'].to01()}")
    print(f"  >> S-Boxes:  S0 = {logF[1]['S0'].to01()}, S1 = {logF[1]['S0'].to01()}")
    print(f"  >> 4-Bit Permutation (P4):  {logF[1]['P4'].to01()}")
    print(f"  >> XOR with Left (Left XOR P4):  {logF[1]['result'][:4].to01()}")
    print(f"  >> Result (XOR with Left || Right):  {logF[1]['result'].to01()}\n")

    print(f"> Inverse Initial Permutation (Ciphertext):  {log['IP-1'].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")

def sdes_dec_results_ui(log: dict, logF: dict, time_elapsed):  
    print("Decrypting Ciphertext:")
    print(f"> Ciphertext Used:  {log['text']}")

    print(f"> Initial Permutation:  {log['IP']}")
    print(f"> Feistel Round 1: Left = {log['IP'][:4].to01()},  Right = {log['IP'][4:].to01()}")
    print(f"  >> Expansion/Permutation (E/P):  {logF[0]['E/P'].to01()}")
    print(f"  >> XOR with SubKey (Right XOR K2):  {logF[0]['xorBitsKey'].to01()}")
    print(f"  >> S-Boxes:  S0 = {logF[0]['S0'].to01()}, S1 = {logF[0]['S0'].to01()}")
    print(f"  >> 4-Bit Permutation (P4):  {logF[0]['P4'].to01()}")
    print(f"  >> XOR with Left (Left XOR P4):  {logF[0]['result'][:4].to01()}")
    print(f"  >> Result (XOR with Left || Right):  {logF[0]['result'].to01()}")
    print(f"> Switch Function (SW):  {log['SW'].to01()}")
    print(f"> Feistel Round 2: Left = {log['SW'][:4].to01()},  Right = {log['SW'][4:].to01()}")
    print(f"  >> Expansion/Permutation (E/P):  {logF[1]['E/P'].to01()}")
    print(f"  >> XOR with SubKey (Right XOR K1):  {logF[1]['xorBitsKey'].to01()}")
    print(f"  >> S-Boxes:  S0 = {logF[1]['S0'].to01()}, S1 = {logF[1]['S0'].to01()}")
    print(f"  >> 4-Bit Permutation (P4):  {logF[1]['P4'].to01()}")
    print(f"  >> XOR with Left (Left XOR P4):  {logF[1]['result'][:4].to01()}")
    print(f"  >> Result (XOR with Left || Right):  {logF[1]['result'].to01()}\n")

    print(f"> Inverse Initial Permutation (Plaintext):  {log['IP-1'].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")

def op_ui():
    while True:
        while True:
            clear_screen()
            print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode")
            print("Choose an option:\n| 1. Electronic Codebook (ECB)\n| 2. Cipher Block Chaining (CBC)\n| 3. Return")
            try:
                choice = int(input("Type the number to select your answer: "))
                if choice in [1, 2, 3]:
                    break
            except ValueError:
                pass

        match choice:
            case 1:
                while True:
                    clear_screen()
                    print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - ECB")
                    print("Choose an option:\n| 1. Use Project Data (No Padding)\n| 2. Type Custom Data (Uses Padding)\n| 3. Return")
                    try:
                        choice = int(input("Type the number to select your answer: "))
                        if choice in [1, 2, 3]:
                            break
                    except ValueError:
                        pass
                title = "Custom Data" if choice == 2 else "Project Data"
                padding = True if choice == 2 else False
                key,plaintext = bitarray(),bitarray()
                if choice == 1:
                    key = bitarray("1010000010")
                    plaintext = bitarray("11010111011011001011101011110000")
                elif choice == 2:
                    while True:
                        clear_screen()
                        print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - ECB, Custom Data")
                        try:
                            inputString = input("Enter 10-bit key: ")
                            if len(inputString) == 10 and is_binary_string(inputString):
                                key = bitarray(inputString)
                                break
                        except ValueError:
                            pass
                
                    while True:
                        clear_screen()
                        print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - ECB, Custom Data")
                        print(f"Enter 10-bit key: {key.to01()}")
                        try:
                            inputString = input("Enter your text (binary): ").replace(" ", "")
                            if is_binary_string(inputString):
                                plaintext = bitarray(inputString)
                                break
                        except ValueError:
                            pass

                if choice in [1,2]:
                    print(f"OPERATION MODES FOR S-DES: Encryption and Decryption Mode - ECB, {title}")
                    print(f"| Key: {key.to01()}")
                    print(f"| Plaintext: {plaintext.to01()}\n")
                    
                    start = time.perf_counter()
                    subKeys = sdes.generateKeys(key)
                    end = time.perf_counter()
                    key_results_ui(sdes.log_keys, (end - start) * 1000)
                    
                    start = time.perf_counter()
                    ciphertext = op.ecb_operation_mode(plaintext, subKeys, 0, padding) 
                    end = time.perf_counter()
                    ecb_enc_results_ui(op.log_ecb, (end - start) * 1000)

                    start = time.perf_counter()
                    plaintext = op.ecb_operation_mode(ciphertext, subKeys, 1, padding) 
                    end = time.perf_counter()
                    ecb_dec_results_ui(op.log_ecb, (end - start) * 1000)

                    input("Press any key to continue")
     
            case 2:
                while True:
                    clear_screen()
                    print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - CBC")
                    print("Choose an option:\n| 1. Use Project Data (No Padding)\n| 2. Type Custom Data (Uses Padding)\n| 3. Return")
                    try:
                        choice = int(input("Type the number to select your answer: "))
                        if choice in [1, 2, 3]:
                            break
                    except ValueError:
                        pass
                title = "Custom Data" if choice == 2 else "Project Data"
                padding = True if choice == 2 else False
                key,iVector,plaintext = bitarray(),bitarray(),bitarray()
                if choice == 1:
                    key = bitarray("1010000010")
                    iVector = bitarray("01010101")
                    plaintext = bitarray("11010111011011001011101011110000")
                elif choice == 2:
                    while True:
                        clear_screen()
                        print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - CBC, Custom Data")
                        try:
                            inputString = input("Enter 10-bit key: ")
                            if len(inputString) == 10 and is_binary_string(inputString):
                                key = bitarray(inputString)
                                break
                        except ValueError:
                            pass

                    while True:
                        clear_screen()
                        print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - CBC, Custom Data")
                        print(f"Enter 10-bit key: {key.to01()}")
                        try:
                            inputString = input("Enter 8-bit initialization vector: ")
                            if len(inputString) == 8 and is_binary_string(inputString):
                                iVector = bitarray(inputString)
                                break
                        except ValueError:
                            pass
                
                    while True:
                        #clear_screen()
                        print("OPERATION MODES FOR S-DES: Encryption and Decryption Mode - CBC, Custom Data")
                        print(f"Enter 10-bit key: {key.to01()}")
                        print(f"Enter 8-bit initialization vector: {iVector.to01()}")
                        try:
                            inputString = input("Enter your text (binary): ").replace(" ", "")
                            print(inputString)
                            if is_binary_string(inputString):
                                plaintext = bitarray(inputString)
                                break
                        except ValueError:
                            pass

                if choice in [1,2]:
                    print(f"OPERATION MODES FOR S-DES: Encryption and Decryption Mode - CBC, {title}")
                    print(f"| Key: {key.to01()}")
                    print(f"| Initialization Vector: {iVector.to01()}")
                    print(f"| Plaintext: {plaintext.to01()}\n")
                    
                    start = time.perf_counter()
                    subKeys = sdes.generateKeys(key)
                    end = time.perf_counter()
                    key_results_ui(sdes.log_keys, (end - start) * 1000)
                    
                    start = time.perf_counter()
                    ciphertext = op.cbc_operation_mode(plaintext, iVector, subKeys, 0, padding) 
                    end = time.perf_counter()
                    cbc_enc_results_ui(op.log_cbc, (end - start) * 1000)

                    start = time.perf_counter()
                    plaintext = op.cbc_operation_mode(ciphertext, iVector, subKeys, 1, padding) 
                    end = time.perf_counter()
                    cbc_dec_results_ui(op.log_cbc, (end - start) * 1000)

                    input("Press any key to continue")

            case _:
                return

def ecb_enc_results_ui(log:dict, time_elapsed):
    print("Encrypting Plaintext:")
    print(f"> Plaintext Used:  {log['text'].to01()}")

    for i in range(len(log["blocks"])):
        print(f"> Block {i + 1}:  {log["blocks"][i].to01()}  --> Enc --> {log["resultBlocks"][i].to01()}")
    
    print(f"\n> Resulting Ciphertext:  {log['result'].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")

def ecb_dec_results_ui(log:dict, time_elapsed):
    print("Decrypting Ciphertext:")
    print(f"> Ciphertext Used:  {log['text'].to01()}")

    for i in range(len(log["blocks"])):
        print(f"> CipherBlock {i + 1}:  {log["blocks"][i].to01()}  --> Dec --> {log["resultBlocks"][i].to01()}")

    print(f"\n> Resulting Plaintext:  {log['result'].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")

def cbc_enc_results_ui(log:dict, time_elapsed):
    print("Encrypting Plaintext:")
    print(f"> Plaintext Used:  {log['text'].to01()}")
    print(f"> Initialization Vector Used:  {log['IV'].to01()}")

    print (f"> Block {1}:  {log["blocks"][0].to01()} XOR IV ({log["IV"].to01()})")
    print (f"  >> Enc --> {log["resultBlocks"][0].to01()}")

    for i in range(1, len(log["blocks"])):
        print (f"> Block {i + 1}:  {log["blocks"][i].to01()} XOR CipherBlock {i} ({log["resultBlocks"][i-1].to01()})")
        print (f"  >> Enc --> {log["resultBlocks"][i].to01()}")
    
    print(f"\n> Resulting Ciphertext:  {log['result'].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")

def cbc_dec_results_ui(log:dict, time_elapsed):
    print("Decrypting Ciphertext:")
    print(f"> Ciphertext Used:  {log['text'].to01()}")
    print(f"> Initialization Vector Used:  {log['IV'].to01()}")

    print (f"> CipherBlock {1}:  {log["blocks"][0].to01()} --> Dec --> XOR IV ({log["IV"].to01()})")
    print (f"  >> Enc --> {log["resultBlocks"][0].to01()}")

    for i in range(1, len(log["blocks"])):
        print (f"> CipherBlock {i + 1}:  {log["blocks"][i].to01()} --> Dec --> {(log["resultBlocks"][i-1] ^ log["resultBlocks"][i]).to01()}")
        print (f"  >> XOR CipherBlock {i} ({log["blocks"][i-1].to01()}) --> {log["resultBlocks"][i].to01()}")
    
    print(f"\n> Resulting Plaintext:  {log['result'].to01()}")
    print(f"> Time Elapsed: {time_elapsed:.4f} ms\n----------------------------------------")
