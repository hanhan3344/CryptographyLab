import random
import time
from prime import getprime
import sys

sys.setrecursionlimit(100000) #将递归深度设置为十万 
#构造字典
dict = {'a':'31','b':'32','c':'33','d':'34','e':'35','f':'36','g':'37',
        'h':'38','i':'39','j':'10','k':'11','l':'12','m':'13','n':'14',
        'o':'15','p':'16','q':'17','r':'18','s':'19','t':'20','u':'21',
        'v':'22','w':'23','x':'24','y':'25','z':'26','1':'41','2':'42',
        '3':'43','4':'44','5':'45','6':'46','7':'47','8':'48','9':'49',
        '0':'40',' ':'50'}

#字符与数字之间的映射转换
def transferToNum(str):
    m = ""
    for d in str:
        m += dict[d]
    return m

def transferTostr(num):
    n = ""
    for i in range(0,len(num),2):
       n += {value:key for key,value in dict.items()}[num[i]+num[i+1]]
    return n

def get_e(fn):
    e = random.randint(2, fn-1)
    while(gcd(e, fn) != 1):
        e = e+1
    return e

def gcd(a,b): # 欧几里德算法
    if a<b:
        t=a
        a=b
        b=t
    while a%b!=0:
        temp=a%b
        a=b
        b=temp
    return b


'''
扩展欧几里的算法
计算 ax + by = 1中的x与y的整数解（a与b互质）
'''
def ext_gcd(a, b):
    if b == 0:
        x1 = 1
        y1 = 0
        x = x1
        y = y1
        r = a
        return r, x, y
    else:
        r, x1, y1 = ext_gcd(b, a % b)
        x = y1
        y = x1 - a // b * y1
        return r, x, y

'''
超大整数超大次幂然后对超大的整数取模
(base ^ exponent) mod n
'''
def exp_mode(base, exponent, n):
    bin_array = bin(exponent)[2:][::-1]
    r = len(bin_array)
    base_array = []
    
    pre_base = base
    base_array.append(pre_base)
    
    for _ in range(r - 1):
        next_base = (pre_base * pre_base) % n 
        base_array.append(next_base)
        pre_base = next_base
        
    a_w_b = __multi(base_array, bin_array, n)
    return a_w_b % n

def __multi(array, bin_array, n):
    result = 1
    for index in range(len(array)):
        a = array[index]
        if not int(bin_array[index]):
            continue
        result *= a
        result = result % n # 加快连乘的速度
    return result

# 生成公钥私钥，p、q为两个超大质数
def gen_key(p, q):
    n = p * q
    fn = (p - 1) * (q - 1)      # 计算与n互质的整数个数 欧拉函数
    e = get_e(fn)
    # e = 65537
    a = e
    b = fn
    x = ext_gcd(a, b)[1]

    if x < 0:
        d = x + fn
    else:
        d = x
    print("公钥:"+"("+str(n)+","+str(e)+")\n私钥:"+"("+str(n)+","+str(d)+")")
    return    (n, e), (n, d)
    
# 加密 m是被加密的信息 加密成为c
def encrypt(m, pubkey):
    n = pubkey[0]
    e = pubkey[1]
    
    c = exp_mode(m, e, n)
    return c

# 解密 c是密文，解密为明文m
def decrypt(c, selfkey):
    n = selfkey[0]
    d = selfkey[1]
    
    m = exp_mode(c, d, n)
    return m
    
    
if __name__ == "__main__":

    print("1.生成>64位的质数p和q(以528位为例):")
    p = getprime(1024)
    print("p:",p)
    q = getprime(1024)
    print("q:",q)

    print("2.生成公钥私钥")
    pubkey, selfkey = gen_key(p, q)

    print("3.输入明文(小写英文与数字的组合[因为只构造了这两者的字典])")
    plaintext = str(input())
    m = int(transferToNum(plaintext))

    print("4.用公钥加密信息")
    c = encrypt(m, pubkey)
    print("密文:",c)
 
    print("5.用私钥解密")
    d = decrypt(c, selfkey)
    print("明文:",transferTostr(str(d)))

