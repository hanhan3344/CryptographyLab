import random
import time
from prime import getprime
import sys

sys.setrecursionlimit(100000) #将递归深度设置为十万 
#构造字典
dic =  {'0': '00', '1': '01', '2': '02', '3': '03', '4': '04', '5': '05',
        '6': '06', '7': '07', '8': '08', '9': '09', 'a': '10', 'b': '11',
        'c': '12', 'd': '13', 'e': '14', 'f': '15', 'g': '16', 'h': '17',
        'i': '18', 'j': '19', 'k': '20', 'l': '21', 'm': '22', 'n': '23',
        'o': '24', 'p': '25', 'q': '26', 'r': '27', 's': '28', 't': '29',
        'u': '30', 'v': '31', 'w': '32', 'x': '33', 'y': '34', 'z': '35',
        'A': '36', 'B': '37', 'C': '38', 'D': '39', 'E': '40', 'F': '41',
        'G': '42', 'H': '43', 'I': '44', 'J': '45', 'K': '46', 'L': '47',
        'M': '48', 'N': '49', 'O': '50', 'P': '51', 'Q': '52', 'R': '53',
        'S': '54', 'T': '55', 'U': '56', 'V': '57', 'W': '58', 'X': '59',
        'Y': '60', 'Z': '61', ' ': '62', 'None': '63', ',': '64', '.': '65',
        '-': '66'}

#字符与数字之间的映射转换
def transferToNum(str):
    m = ""
    for d in str:
        m += dic[d]
    return m

def transferTostr(num):
    n = ""
    for i in range(0,len(num),2):
       n += {value:key for key,value in dic.items()}[num[i]+num[i+1]]
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


def ext_gcd(a, b): # 扩展欧几里德算法
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


def __multi(array, bin_array, n):
    result = 1
    for index in range(len(array)):
        a = array[index]
        if not int(bin_array[index]):
            continue
        result *= a
        result = result % n # 加快连乘的速度
    return result

def quick_pow(m,e,n): # 快速取幂模
    ans = 1
    while e:
        if e & 1:
            ans = (ans * m) % n
        m = m * m % n
        e >>= 1
    return ans

# 生成公钥私钥，p、q为两个超大质数
def gen_key(p, q):
    n = p * q
    fn = (p - 1) * (q - 1)      # 计算与n互质的整数个数 欧拉函数
    e = get_e(fn)
    # e = 65537
    a = e
    b = fn
    x = ext_gcd(a, b)[1]
    # x = Extended_Euclid(e, fn)

    if x < 0:
        d = x + fn
    else:
        d = x
    print("公钥:"+"("+str(n)+","+str(e)+")\n私钥:"+"("+str(n)+","+str(d)+")")
    return (e, n), (d, n)
    
# 加密 m:str是被加密的信息 加密成为c:str
def encrypt(m, pubkey):
    e = pubkey[0]
    n = pubkey[1]
    c = ''
    std_c_part_len = 0
    g_num = len(m) // 4
    rest = len(m) % 4
    for i in range (0, g_num):
        m_part = int(m[i*4: i*4+4])
        c_part = str(quick_pow(m_part, e, n))
        c_part_len = len(c_part)
        if(i == 0):
            std_c_part_len = c_part_len + 8
        numof0 = std_c_part_len - c_part_len

        if(numof0 != 0):
            c_part = '0'*numof0 + c_part
        # print('len(c_part) = %d'%(len(c_part)))
        c += c_part
    if(rest != 0):
        m_part = int(m[g_num*4: g_num*4+2] + '63')
        # print('rest m_part = %d'%(m_part))
        c_part = str(quick_pow(m_part, e, n))
        # print('rest c_part = %s'%(c_part))
        c_part_len = len(c_part)
        numof0 = std_c_part_len - c_part_len
        if(numof0 != 0):
            c_part = '0'*numof0 + c_part
        # print('len(c_part) = %d'%(len(c_part)))
        c += c_part
    # c = exp_mode(m, e, n)
    return c, std_c_part_len

# 解密 c:str是密文，解密为明文m:str
def decrypt(c, selfkey, c_part_len):
    d = selfkey[0]
    n = selfkey[1]
    m = ''
    g_num = len(c) // c_part_len
    # print('len(c) = %d, c_part_len = %d'%(len(c), c_part_len))
    # print('g_num = %d'%(g_num))
    for i in range(0, g_num):
        c_part = int(c[i*c_part_len: i*c_part_len+c_part_len])
        m_part = str(quick_pow(c_part, d, n))
        if(len(m_part) != 4):
            m_part = (4-len(m_part))*'0' + m_part
        # print('m_part = %s'%(m_part))
        m += m_part
    # if(c[len(m)-2: len(m)] == '63'):
    #     c_part = int(c[(g_num-1)*4: (g_num-1)*4+2])
    # else:
    #     print('################', c[(g_num-1)*4: (g_num-1)*4+4])
    #     c_part = int(c[(g_num-1)*4: (g_num-1)*4+4])
    # m_part = str(quick_pow(c_part, d, n))
    # m += m_part
    # m = exp_mode(c, d, n)
    if(m[len(m)-2: len(m)] == '63'):
        m = m[0: len(m)-2]
    return m
    
    
if __name__ == "__main__":

    print("1.生成>64位的质数p和q(1024位):")
    p = getprime(1024)
    print("p:",p)
    q = getprime(1024)
    print("q:",q)

    print("2.生成公钥私钥")
    pubkey, selfkey = gen_key(p, q)

    print("3.读取明文(lab2-Plaintext.txt)")
    with open("lab2-Plaintext.txt", "r", encoding='utf-8') as f:
        plaintext = f.read()
    # plaintext = str(input())
    f.close()
    m = transferToNum(plaintext)

    print("4.用公钥加密信息")
    c, c_part_len = encrypt(m, pubkey)
    print("密文:",c)
 
    print("5.用私钥解密")
    d = decrypt(c, selfkey, c_part_len)
    # print('d = %s'%(d))
    print("明文:",transferTostr(d))

