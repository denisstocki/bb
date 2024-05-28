import random
from itertools import combinations

def calculateAccountControlNumber(nr):
    weights = [3, 9, 7, 1, 3, 9, 7]
    control_sum = sum(n * w for n, w in zip(nr, weights))
    return (10 - (control_sum % 10)) % 10

def calculateAccountControlNumber2(nr):
    sum = 0
    for char in nr:
        sum = (sum * 10 + int(char)) % 97
    return 98 - sum % 97

def generateBankAccounts(limit):
    accounts = []
    bankIds = [
        [1, 0, 1, 0, 0, 0, 0, 0],  # NBP
        [1, 1, 6, 0, 0, 0, 0, 6],  # Millenium 
        [1, 0, 5, 0, 0, 0, 0, 2],  # ING
        [2, 1, 2, 0, 0, 0, 0, 1],  # Santander
        [1, 0, 2, 0, 0, 0, 0, 3],  # PKO BP
    ]

    rng = random.Random(2137)

    for nr in bankIds:
        for _ in range(limit):
            bankNumber = ""
            clientNumber = [rng.randint(0, 9) for _ in range(16)]

            partBankNumber = nr + clientNumber

            controlSum = calculateAccountControlNumber2(partBankNumber)

            bankNumber += str(controlSum)
            bankNumber += ''.join(map(str, nr))
            bankNumber += ''.join(map(str, clientNumber))

            accounts.append(bankNumber)

    return accounts


def rc4(key, data):
    s = list(range(256))
    j = 0

    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    cryptogram = []

    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        cryptogram.append(byte ^ k)

    return bytes(cryptogram)

def useCommonRc4Key(cryptogram1, cryptogram2):
    minLen = min(len(cryptogram1), len(cryptogram2))

    for i in range(minLen):
        if (cryptogram1[i] ^ cryptogram2[i]) >= 0x80:
            return False
        
    return True

def zadanie1():
    key = b"This guy is a key."
    key0 = b"This guy is a key0."
    key1 = b"This guy is a key1."
    data = b"This is my data."

    dataRc4Encoded = rc4(key, data)
    dataRc4Decoded = rc4(key, dataRc4Encoded)

    key_str = key.decode('utf-8')
    data_str = data.decode('utf-8')
    dataRc4Encoded_str = dataRc4Encoded.hex()  # Możemy użyć kodowania hex
    dataRc4Decoded_str = dataRc4Decoded.decode('utf-8')

    print("######## ZADANIE 1 ########")
    print(f"Key:            {key_str}")
    print(f"Data:           {data_str}")
    print(f"RC4 Encoded:    {dataRc4Encoded_str}")
    print(f"RC4 Decoded:    {dataRc4Decoded_str}")
    print()
    for _ in range(10):
        data = bytearray(random.getrandbits(8) for _ in range(1024))
        ciphertext0 = rc4(key0, data)
        ciphertext1 = rc4(key1, data)
        plaintext0 = rc4(key0, ciphertext0)
        plaintext1 = rc4(key1, ciphertext1)
        assert data == plaintext0, "Decryption with key0 failed"
        assert data == plaintext1, "Decryption with key1 failed"
    print("Testing has been passed!")
    print("######## ZADANIE 1 ########")
    print()

def zadanie2():
    key1 = b"This guy is a key nr 1."
    key2 = b"This guy is a key nr 2."
    data1 = b"This is my data nr 1."
    data2 = b"This is my data nr 2."

    data1WithKey1Encoded = rc4(key1, data1)
    data1WithKey2Encoded = rc4(key2, data1)
    data2WithKey1Encoded = rc4(key1, data2)
    data2WithKey2Encoded = rc4(key2, data2)

    print("######## ZADANIE 2 ########")
    print(f"(Data1 -> Key1) & (Data1 -> Key2): {useCommonRc4Key(data1WithKey1Encoded, data1WithKey2Encoded)}")
    print(f"(Data1 -> Key1) & (Data2 -> Key1): {useCommonRc4Key(data1WithKey1Encoded, data2WithKey1Encoded)}")
    print(f"(Data1 -> Key1) & (Data2 -> Key2): {useCommonRc4Key(data1WithKey1Encoded, data2WithKey2Encoded)}")
    print("######## ZADANIE 2 ########")
    print()

def zadanie3():
    accounts = generateBankAccounts(3)
    key = b"This guy is a key."
    cryptograms = []

    for bank_number in accounts:
        cryptogram = rc4(key, bank_number.encode('utf-8'))
        cryptograms.append(cryptogram)
    
    print("######## ZADANIE 3 ########")
    for c0, c1 in combinations(cryptograms, 2):
        xored = [i0 ^ i1 for i0, i1 in zip(c0, c1)]
        print(xored[2:10])

    print("######## ZADANIE 3 ########")

def main():
    zadanie1()
    zadanie2()
    zadanie3()

if __name__ == "__main__":
    main()