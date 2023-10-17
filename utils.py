import base64
from collections import Counter
import math
from itertools import combinations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



def hex2base64(x: str) -> str:
    x = bytes.fromhex(x)
    x = base64.b64encode(x)
    return x

def xor(a, b):
    return bytes([a_ ^ b_ for a_, b_ in zip(a,b)])

def repeatingKeyXOR(x, key):
    xlen = len(x)
    repKey = key*xlen
    return xor(x, repKey)

def get_score(x, letterFreq):
    len_cyphertext = len(x)
    bytesFreq = {int.to_bytes(k, 1, byteorder='big').lower(): v/len_cyphertext for k, v in Counter(x).items()}
    freqDiff = 0
    for byte, byteFreq in bytesFreq.items():
        if byte in letterFreq:
            freqDiff += abs(letterFreq[byte] - byteFreq)**2
        else:
            freqDiff += 1
    return freqDiff/len(bytesFreq)

def crack(x, letterFreq, tryLuck=False):
    shape_text = len(x)
    all_possible_bytes = [int.to_bytes(i, length=1, byteorder='big') for i in range(256)]
    
    if tryLuck:
        min_ = 1
        for byte in all_possible_bytes:
            key = byte*shape_text
            xored = xor(x, key)
            score = get_score(xored, letterFreq)
            if score < min_:
                min_ = score
                results = {xored: (score, key)}
    else:
        results = {}
        for byte in all_possible_bytes:
            key = byte*shape_text
            xored = xor(x, key)
            results[xored] = (get_score(xored, letterFreq), key)
            results = dict(sorted(results.items(), key=lambda item: item[1][0]))
    return results

def hamming(x, y):
    assert len(x)==len(y), 'x and y should have the same length'
    x = [int(bit) for byte in x for bit in bin(byte)[2:].rjust(8, '0')]
    y = [int(bit) for byte in y for bit in bin(byte)[2:].rjust(8, '0')]
    return sum([x_!=y_ for x_, y_ in zip (x, y)])

def guess_keysize(file, nChunks):
    average_over = math.factorial(nChunks)/(2*math.factorial(nChunks-2))
    scores = []
    min_ = 2**8*40
    guessed_keysize = None
    for keysize in range(2, 40):
        chunks = [file[i*keysize:(i + 1)*keysize] for i in range(nChunks)]
        score = sum([hamming(comb[0], comb[1])/keysize 
                    for comb in combinations(chunks, 2)]) / average_over
        scores.append(score)
        if score < min_:
            guessed_keysize = keysize
            min_ = score
    return scores, guessed_keysize

class PKCS7:
    def __init__(self, block_size):
        self.block_size = block_size

    def pad(self, text):
        n = self.block_size - len(text) % self.block_size
        return text + bytes([n] * n)
    
    def unpad(self, text):
        n = text[-1]
        return text[:-n]
    
class PKCS7:
    def __init__(self, block_size):
        self.block_size = block_size

    def pad(self, text):
        n = self.block_size - len(text) % self.block_size
        return text + bytes([n] * n)
    
    def validPad(self, text):
        text = text[-self.block_size:]
        n = text[-1]
        if text[-n:] == bytes([n]) * n:
            return True
        else:
            raise Exception('Invalid Padding')
    
    def unpad(self, text):
        if self.validPad(text):
            n = text[-1]
            return text[:-n]
    
class AES_CBC:
    def __init__(self, key, IV):
        self.key = key
        self.IV = IV
        self.cipher = Cipher(
            algorithm=algorithms.AES(self.key),
            mode=modes.ECB()
        )
        self.block_size = int(self.cipher.algorithm.block_size/8)
        self.padding = PKCS7(self.block_size)
        

    def _pass_through_cipher(self, text, mode):
        if mode == 'encrypt':
            cipher = self.cipher.encryptor()
            text = self.padding.pad(text)
        elif mode == 'decrypt':
            cipher = self.cipher.decryptor()
        else:
            raise('Wrong mode')
        
        blocks = [text[i:i+self.block_size] for i in 
                  range(0, len(text), self.block_size)]
        cipherText = b''
        for i, block in enumerate(blocks):
            if i == 0:
                prevBlock = self.IV

            if mode == 'encrypt':
                block = xor(prevBlock, block)
                cipherBlock = cipher.update(block)
                prevBlock = cipherBlock
            elif mode == 'decrypt':
                cipherBlock = cipher.update(block)
                cipherBlock = xor(prevBlock, cipherBlock)
                prevBlock = block
            cipherText += cipherBlock
        if mode == 'decrypt':
            cipherText = self.padding.unpad(cipherText)
        return cipherText

    def encrypt(self, plainText):
        return self._pass_through_cipher(plainText, 'encrypt')
    
    def decrypt(self, cipherText):
        return self._pass_through_cipher(cipherText, 'decrypt')
    
def check_repetitions_ECB(cipherText, blockSize):
    blocks = [cipherText[i:i+blockSize] for i in range(0, len(cipherText), blockSize)]
    for block in blocks:
        if len(blocks) != len(set(blocks)):
            return True
        else:
            return False
        
def find_padding_length(oracle):
    stop = False
    startingLen = len(oracle(b''))
    i = 1
    while not stop:
        newLen = len(oracle(b'A'*i))
        if newLen != startingLen:
            stop = True
        else:
            i += 1
    blockSizeFound = newLen - startingLen
    return blockSizeFound