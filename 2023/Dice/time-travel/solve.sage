with open("input.bin", "rb") as f:
    raw_data = f.read()
    N = int.from_bytes(raw_data[:4], byteorder="little")
    raw_data = raw_data[4:]
    data = [int.from_bytes(raw_data[8 * i: 8 * (i + 1)], byteorder="little") for i in range(len(raw_data) // 8)]
assert N == 0x12
assert 0x90 == N * 0x8

flag = b""
for i in range(64):
    m = []
    for j in range(N):
        row = data[325 * i + N * j: 325 * i + N * (j + 1)]
        m.append(row)
    M = matrix(IntegerModRing(256), m)
    d = M.determinant()
    c = data[325 * i + N * N] - d + i
    flag += chr(c).encode()

assert flag == b"dice{d3t4rm1n1NanT5_c4n_b3_F4sT_1a7sN2j1867327mA6jmapc817jgd6m0}"
print(flag)
