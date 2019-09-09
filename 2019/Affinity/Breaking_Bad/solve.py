ct = "HoRfSbMtInMcLvFlAcAmInMcAmTeErFmInHoLvDbRnMd"
ct = [ct[2 * i:2 * (i + 1)] for i in range(len(ct) // 2)]
# ['Ho', 'Rf', 'Sb', 'Mt', 'In', 'Mc', 'Lv', 'Fl', 'Ac', 'Am', 'In', 'Mc', 'Am', 'Te', 'Er', 'Fm', 'In', 'Ho', 'Lv', 'Db', 'Rn', 'Md']
# Corresponds to Periodic table

flag = "Ch3m1strY_1s_4Dd1CtiVe"
flag = "AFFCTF{" + flag + "}"

flag == "AFFCTF{Ch3m1strY_1s_4Dd1CtiVe}"
print(flag)
