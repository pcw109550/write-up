from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time, random, sys

FLAG = "cce2023{cce_schedule_20230610_0900_2000!!}".encode()
Message = "Hello, Alice!. My flag is here.".encode()


def encrypt(P, K):
    aesCipher = AES.new(key=K, mode=AES.MODE_ECB)

    N = FLAG[:len(FLAG) // 2]
    Counter = hex(0x00)[2:].zfill(16).encode()
    keyStream = aesCipher.encrypt(pad(N + Counter, 16))

    return int.from_bytes(keyStream, byteorder='big') ^ int.from_bytes(P, byteorder='big')


if __name__ == '__main__':
    random.seed(time.time())

    # I looking forward to the secret Key, which is very very safety
    while True:
        K = f"{int(random.random() * 10000000)}".encode()
        K += "ABCDEFABC".encode()

        if len(K) == 16:
            break
    
    try:
        print(f"My Message! : {encrypt(P=Message, K=K)}")
        print(f"My FLAG! : {encrypt(P=FLAG[len(FLAG) // 2:], K=K)}")
    finally:
        sys.exit()