from config import ct
from base64 import b64decode

b64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

h = ""
for c in ct:
    h += b64table[c.bit_length() - 2]

flag = b64decode(h)
assert flag == "ISITDTU{r1c3_che55b0ard_4nd_bs64}"

print(flag)
