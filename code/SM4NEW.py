def sbox(a):
    s=['d690e9fecce13db716b614c228fb2c05',
       '2b679a762abe04c3aa44132649860699',
       '9c4250f491ef987a33540b43edcfac62',
       'e4b31ca9c908e89580df94fa758f3fa6',
       '4707a7fcf37317ba83593c19e6854fa8',
       '686b81b27164da8bf8eb0f4b70569d35',
       '1e240e5e6358d1a225227c3b01217887',
       'd40046579fd327524c3602e7a0c4c89e',
       'eabf8ad240c738b5a3f7f2cef96115a1',
       'e0ae5da49b341a55ad933230f58cb1e3',
       '1df6e22e8266ca60c02923ab0d534e6f',
       'd5db3745defd8e2f03ff6a726d6c5b51',
       '8d1baf92bbddbc7f11d95c411f105ad8',
       '0ac13188a5cd7bbd2d74d012b8e5b4b0',
       '8969974a0c96777e65b9f109c56ec684',
       '18f07dec3adc4d2079ee5f3ed7cb3948']
    b=''
    for i in range(4):
        r=int(a[2*i],16)
        c=int(a[2*i+1],16)
        b=b+s[r][c*2:(c+1)*2]
    return int(b,16)

def cl(x,i):#Cycle left
    x='{:032b}'.format(x)
    i=i%32
    x=x[i:]+x[:i]
    return int(x,2)

fk=[int('A3B1BAC6',16),int('56AA3350',16),int('677D9197',16),int('B27022DC',16)]
ck=[]
for i in range(32):
    cki=[]
    for j in range(4):
        cki.append('{:02x}'.format(((4*i+j)*7)%256))
    ck.append(int(''.join(cki),16))
'''
ck=['00070e15','1c232a31','383f464d','545b6269',
    '70777e85','8c939aa1','a8afb6bd','c4cbd2d9',
    'e0e7eef5','fc030a11','181f262d','343b4249',
    '50575e65','6c737a81','888f969d','a4abb2b9',
    'c0c7ced5','dce3eaf1','f8ff060d','141b2229',
    '30373e45','4c535a61','686f767d','848b9299',
    'a0a7aeb5','bcc3cad1','d8dfe6ed','f4fb0209',
    '10171e25','2c333a41','484f565d','646b7279']
'''
def f(x,rk,i):
    return x[i]^t(x[i+1]^x[i+2]^x[i+3]^rk)

def t(x):
    return l(tau(x))
def t_(x):#t'
    return l_(tau(x))

def tau(a):
    a='{:08x}'.format(a)
    b=sbox(a)
    return b

def l(b):
    c=b^cl(b, 2)^cl(b, 10)^cl(b, 18)^cl(b, 24)
    return c
def l_(b):#l'
    c=b^cl(b, 13)^cl(b, 23)
    return c

def enc(x,mk):
    if len(x)!=32:
        x=x+(32-len(x))*'0'
    p=[x[:8],x[8:16],x[16:24],x[24:]]
    x=p
    for i in range(len(x)):
        x[i]=int(x[i],16)
    rk=kea(mk, fk, ck)
    for i in range(32):
        #print('rk['+'{:02d}'.format(i)+'] = '+'{:08x}'.format(rk[i]),end='   ')
        x.append(f(x,rk[i],i))
        #print('x['+'{:02d}'.format(i)+'] = '+'{:08x}'.format(x[-1]))
    #print()
    y=x[32:][::-1]
    for i in range(len(y)):
        y[i]='{:08x}'.format(y[i])
    y=''.join(y)
    return y

def kea(mk,fk,ck):#Key extension algorithm
    if len(mk)!=32:
        mk=(32-len(mk))*'0'+mk
    p=[mk[:8],mk[8:16],mk[16:24],mk[24:]]
    mk=p
    for i in range(len(mk)):
        mk[i]=int(mk[i],16)
    k=[]
    for i in range(4):
        k.append(mk[i]^fk[i])
    for i in range(32):
        k.append(k[i]^t_(k[i+1]^k[i+2]^k[i+3]^ck[i]))
    rk=k[4:]
    return rk

if __name__=='__main__':
    # p=input('Your plaintext(hex):')
    p="616161"
    # mk=input('Your encryption key(hex):')
    mk="F2D8D966CD3D47788449C19D5EF2081B"
    print()
    y=enc(p, mk)
    print('Ciphertext:',end=(' '))
    for i in range(4):
        print(y[i*8:(i+1)*8],end=' ')
    print()
