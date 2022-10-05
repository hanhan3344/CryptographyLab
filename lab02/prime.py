import random
from random import randint


#幂模运算
def X_n_mod_P(base, exponent, n):
    # print('bin(exponent = )', bin(exponent))
    bin_array = bin(exponent)[2:][::-1] # 从数字位开始反转
    # print('bin_array = ', bin_array)
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
        if int(bin_array[index]):
            result *= a
            result = result % n # 加快连乘的速度
        else:
            continue
    return result

def MillerRabin(a, p):  #素性测试
    if X_n_mod_P(a, p - 1, p) == 1:
        u = (p-1) >> 1
        while (u & 1) == 0:
            t = X_n_mod_P(a, u, p)
            if t == 1:
                u = u >> 1
            else:
                if t == p - 1:
                    return True
                else:
                    return False
        else: # p-1除成奇数
            t = X_n_mod_P(a, u, p)
            if t == 1 or t == p - 1:
                return True
            else:
                return False
    else:
        return False

def testMillerRabin(p, k):  # k为测试次数，p为待测奇数
    for i in range(0, k):
        a = randint(2, p - 1)
        if not MillerRabin(a, p):
            return False
    return True

def getprime(w):           # 产生w位素数
    while 1:
        list = [] # 随机数产生
        list.append('1')  # 最高位定为1
        for _ in range(w - 2):
            c = random.choice(['0', '1'])
            list.append(c)
        list.append('1') # 最低位定为1
        d = int(''.join(list),2)
        # d = proBin(w)
        for i in range(50):  # 伪素数附近50个奇数都没有真素数的话，重新再产生一个伪素数
            u = testMillerRabin(d+2*(i), 5)
            if u:
                b = d + 2*(i)
                break
            else:
                continue
        if u:
            return b
        else:
            continue
if __name__ == "__main__":   #测试
     print(getprime(67))

