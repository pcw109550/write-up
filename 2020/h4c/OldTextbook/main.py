from secrets import randbelow,randbits
from math import gcd,log2,ceil

def is_prime(p,hardness=1000):
    for _ in range(hardness):
        a=randbelow(p-1)+1
        if gcd(a,p)!=1 or pow(a,p-1,p)!=1:
            return False
    return True

def generate_pub_key(bits):
    p,q=randbits(bits//2),randbits(bits//2)
    p = p+1 if p%2==0 else p
    q = q+1 if q%2==0 else q
    while not is_prime(p):
        p-=randbelow(10)*2+2
    while not is_prime(q):
        q-=randbelow(10)*2+2
    return p*q

def main():
    e=65537
    with open("flag","rb") as k:
        pt=k.read()
        assert pt[:4]==b'h4c(' and pt[-1:]==b')'

    pts=[pt[i*63:i*63+63] for i in range((len(pt)-1)//63+1)]

    for blk in pts:
        m=int.from_bytes(blk,byteorder='big')
        n=generate_pub_key(2**ceil(log2(log2(m))))
        print(pow(m,e,n),e,n)

if __name__ == "__main__":
    main()