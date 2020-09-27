from Crypto.Cipher import AES
import hashlib

ENCRYPTED = b'\xA5\xD1\xDB\x88\xFD\x34\xC6\x46\x0C\xF0\xC9\x55\x0F\xDB\x61\x9E\xB9\x17\xD7\x0B\xC8\x3D\xE5\x1B\x09\x71\xAE\x5F\x1C\xB5\xC7\x2C\xC5\x3F\x5A\xA7\xFB\xED\x63\xE6\xAD\x04\x0D\x16\xF6\x33\x16\x01'
assert len(ENCRYPTED) == 48
assert len('___FLAGHEADER___') == 16

def Check(buf, ml, cl):
    if ml != cl:
        for ch in range(0,100):
            buf[cl] = ch
            Check(buf, ml, cl+1)
        return

    for ch in range(0,100):
        buf[cl] = ch
        tmpBuf = bytes(buf)

        aes1 = AES.new(hashlib.sha256(tmpBuf[0:4]).digest(), AES.MODE_ECB)
        aes2 = AES.new(hashlib.sha256(tmpBuf[4:8]).digest(), AES.MODE_ECB)

        myBuf = aes1.decrypt(aes2.decrypt(ENCRYPTED))

        if myBuf[0:16] == b"___FLAGHEADER___":
            print("The Flag is... ",end="")
            print(myBuf[16:])

def main():
    buf = [0,0,0,0,0,0,0,0]
    Check(buf, 7, 0)

if __name__ == "__main__":
    main()
