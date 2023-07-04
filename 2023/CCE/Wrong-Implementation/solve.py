import pwn
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
from tqdm import tqdm

IP, PORT = "20.214.200.9", 18080
Message = "Hello, Alice!. My flag is here.".encode()
# 31 byte
shift = bytes_to_long(Message)

pwn.context.log_level = "DEBUG"
tn = pwn.remote(IP, PORT)
msg = int(tn.recvline().split()[-1])
enc_flag = int(tn.recvline().split()[-1])
tn.close()

# msg, enc_flag is 48 byte or 384 bit

flag_lower = long_to_bytes(msg ^ enc_flag ^ shift)
assert len(flag_lower) == 21
print(flag_lower)
# flag length : 42

Counter = hex(0x00)[2:].zfill(16).encode()
dummy = pad(b"\x00" * len(flag_lower) + Counter, 16)
assert len(dummy) == 48

pt_oracle = dummy[-16:]
ct_oracle = long_to_bytes(
    bytes_to_long(Message[-16:]) ^ bytes_to_long(long_to_bytes(msg)[-16:])
)


def recover_key(pt_oracle: bytes, ct_oracle: bytes) -> bytes:
    PAD = b"ABCDEFABC"
    for key_cand in tqdm(range(1000000, 10000000)):
        KEY_CAND = str(key_cand).encode() + PAD
        aesCipher = AES.new(key=KEY_CAND, mode=AES.MODE_ECB)
        ct_cand = aesCipher.encrypt(pt_oracle)
        if ct_cand != ct_oracle:
            continue
        return KEY_CAND
    assert False, "key search failure"


KEY = recover_key(pt_oracle, ct_oracle)
keystream = long_to_bytes(bytes_to_long(Message) ^ msg)
aesCipher = AES.new(key=KEY, mode=AES.MODE_ECB)
pt = aesCipher.decrypt(keystream)
flag_upper = pt[:21]

flag = flag_upper + flag_lower
print(flag)
