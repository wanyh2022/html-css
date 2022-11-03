
class SM4(object):
    def __init__(self):
        """ .    : 输入
           xor  ： 异或，
           <<<i  : 32位循环左移i位,
           S盒   : s盒为固定的8比特输出的置换,记为Sbox(.)
           """
        self.SboxTable = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
        ]

        self.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        self.CK = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        ]
    def Circular_shift_left(self,value=0,left_bit=0):
        """循环左移函数,循环左移位数为32位,
           vlaue:初始数据,
           left_bit:左移位数"""
        if value > 256 ** 4:
            return 0
        left_bit = left_bit % 32
        return_value = ((value << left_bit) | (value >> (32 - left_bit))) & 0x00000000ffffffff
        return return_value
    def Xor_fuction(self,*kwargs):
        """异或函数，传入多个参数 x1,x2,x3,..，
           将多个参数组合成一个元组（x1,x2,x3,...)进行异或操作
           x1 xor x2 xor x3 xor ..."""
        len_kwargs=len(kwargs)
        return_value=kwargs[0]
        for i in range(1,len_kwargs):
            return_value=kwargs[i]^return_value #^:异或操作符
        return return_value
    def T_function(self,A="0x"):       #T_fuction以下简称T
        """合成置换函数T，由非线性变换t合线性变换L复合而成，即T(.)=L(t(.)),
            .:点为输入的32位的值，函数T返回T(.)=B，一个32位的值,
        输入A:一个32位的值,数据类型为字符串，A=(a0,a1,a2,a3),
        非线性变换t:输入A,输出为B=(b0,b1,b2,b3)
                   即(b0,b1,b2,b3)=t(A)=(Sbox(a0),Sbox(a1),Sbox(a2),Sbox(a3))
        Sbox(a):输入一个8位的值，通过查Sbox表（Sbox一个一直的表)，返回一个8位的值.
        线性变换L:t的输出，是L的输入,C=L(B)=B xor (B<<<2) xor (B<<<10) xor (B<<<18) xor (B<<<24),
                    即C=L(t(.))=t(.) xor (t(.)<<<2) xor (t(.)<<<10) xor (t(.)<<<18) xor (t(.)<<<24)"""
        pass


    def Key_expansion_algorithm(self,mk=(0x01234567,0x89abcdef,0xfedcba98,0x76543210)):
        """密钥扩展算法，返回密钥
           输入一个元组类型的密钥:MK=(MK0,MK1,MK2,MK3),MK一共32*4=128位
           (K0,K1,K2,K3)=(MK0 xor FK0,MK1 xor FK1,MK2 xor FK2,MK3 xor FK3),
           rk_i=K_i+4=K_i xor T'(K_i+1 xor K_i+2 xor K_i+3 xor CK_i ),i=0,1,2,...,31),
           T'()="""
        MK=list(mk)     #初始化加密密钥
        rk=[]   #用来记录每一组的密钥rk_i,i=0,1,...,31
        K_list=[]#用来记录每一组的字K_i,i=0,1,...,35

        for i in range(4):
            k=self.Xor_fuction(MK[i],self.FK[i])
            K_list.append(k)   #获得初始的K0,K1,K2,K3
            #(K0,K1,K2,K3)=(MK0 xor FK0,MK1 xor FK1,MK2 xor FK2,MK3 xor FK3),

        for i in range(32):
            K_xor=self.Xor_fuction(K_list[i+1],K_list[i+2],K_list[i+3],self.CK[i])

            end_B=0 #end_B记录通过分组查询Sbox表获得的k_sbox组装，获得最终非线性变换的值
            # print(hex(K_xor))
            for j in range(4):
                index=int((K_xor & (0xff000000 >> j*8)) / 256 ** (3-j)) #获得该值在Sbox表对应的索引
                end_B=256**(3-j)*self.SboxTable[index]+end_B  #用于分组查询Sbox表
                # print(hex(index),hex(self.SboxTable[index]),hex(end_B))
            end_B=int(end_B)

            # end_T记录最终合成置换T'()的值
            end_T=self.Xor_fuction(end_B, self.Circular_shift_left(end_B, 13), self.Circular_shift_left(end_B, 23))
            # print(hex(end_T))

            #rk_i获得一组轮密钥的值
            rk_i=self.Xor_fuction(K_list[i],end_T)

            K_list.append(rk_i)
            rk.append(rk_i)

        # for i in range(32):
        #     print("rk[%d]"%i,"=",str(hex(rk[i])).upper())

        return rk #返回一个轮密钥列表rk=[i],i=0,1,..,31

    def encryption_main(self,X=(0x01234567,0x89abcdef,0xfedcba98,0x76543210),
                        mk=(0x01234567,0x89abcdef,0xfedcba98,0x76543210)):
        """加密算法，输入明文，利用SM4加密算法,返回最终密文，
           X:初始明文(要加密的128bit数据),
           mk:初始密钥(要加密的128bit密钥)"""
        rk=self.Key_expansion_algorithm(mk)

        X_list = list(X)  #  X_list=[]记录每一组的密文,初始化加密密钥



        for i in range(32):
            X_xor = self.Xor_fuction(X_list[i + 1], X_list[i + 2], X_list[i + 3], rk[i])
            end_B = 0  # end_B记录通过分组查询Sbox表获得的k_sbox组装，获得最终非线性变换的值

            for j in range(4):
                index = int((X_xor & (0xff000000 >> (j * 8))) / 256 ** (3 - j))  # 获得该值在Sbox表对应的索引
                end_B = 256 ** (3 - j) * self.SboxTable[index] + end_B  # 用于分组查询Sbox表

            end_B = int(end_B)
            # end_T记录最终合成置换T'()的值
            end_T = self.Xor_fuction(end_B, self.Circular_shift_left(end_B, 2), self.Circular_shift_left(end_B, 10),
                                     self.Circular_shift_left(end_B, 18),self.Circular_shift_left(end_B, 24))

            # X_i获得一组密文的值
            X_i = self.Xor_fuction(X_list[i], end_T)
            X_list.append(X_i)

        # for i in range(36):
        #     print("X[%d]" % i, "=", str(hex(X_list[i])).upper())]
        #Y_list:最终密文
        Y_str=""
        for i in range(35,31,-1):
            str_X_i=str(hex(X_list[i]))[2:] #去除0x这两个字符
            Y_str= Y_str + "0"*(8-len(str_X_i)) + str_X_i
        return Y_str

    def decrypt_main(self,Y=(0x681edf34,0xd206965e,0x86b3e94f,0x536e4246),
                        mk=(0x01234567,0x89abcdef,0xfedcba98,0x76543210)):
        """解密算法，输入密文，利用SM4解密算法,返回最终明文，
            解密算法与加密算法基本相同，所以代码ctrl c 加 ctrl v
           X:初始密文(要解密的128bit数据),
           mk:初始密钥(要解密的128bit密钥)"""
        MK=[]
        for i in range(4):
            MK.append(mk[3-i])

        rk = self.Key_expansion_algorithm(mk)
        X=Y
        """
        #以下代码基本复制函数encryption_main，只改动了rk[i]-->rk[31-i]
        """
        X_list = list(X)  # X_list=[]记录每一组的密文,初始化加密密钥

        for i in range(32):
            X_xor = self.Xor_fuction(X_list[i + 1], X_list[i + 2], X_list[i + 3], rk[31-i])
            end_B = 0  # end_B记录通过分组查询Sbox表获得的k_sbox组装，获得最终非线性变换的值

            for j in range(4):
                index = int((X_xor & (0xff000000 >> (j * 8))) / 256 ** (3 - j))  # 获得该值在Sbox表对应的索引
                end_B = 256 ** (3 - j) * self.SboxTable[index] + end_B  # 用于分组查询Sbox表

            end_B = int(end_B)
            # end_T记录最终合成置换T'()的值
            end_T = self.Xor_fuction(end_B, self.Circular_shift_left(end_B, 2), self.Circular_shift_left(end_B, 10),
                                     self.Circular_shift_left(end_B, 18), self.Circular_shift_left(end_B, 24))

            # X_i获得一组密文的值
            X_i = self.Xor_fuction(X_list[i], end_T)
            X_list.append(X_i)

        # for i in range(36):
        #     print("X[%d]" % i, "=", str(hex(X_list[i])).upper())]
        # Y_list:最终密文

        Y_str = ""
        for i in range(35, 31, -1):
            str_X_i = str(hex(X_list[i]))[2:] #去除0x这两个字符
            Y_str =Y_str +  "0" * (8 - len(str_X_i)) + str_X_i
        return Y_str

def str_tuple(str,byte=4):
    """字符串转元组，如
        '0123456789abcdeffedcba9876543210',
        (0x01234567,0x89abcdef,0xfedcba98,0x76543210),
        str:输入一个十六进制类型的字符串,最好len(str)=32个字符
        byte:分割的,每一段的字节数,如当byte=4时,0x01234567占4个字节
        函数返回值:返回一个一共128bit(32个字符)的元组
        """
    str="0"*(32-len(str))+str
    encryption_X = []
    byte=byte*2
    for j in range(32//byte):
        encryption_X.append(int('0x' + str[j * byte:(j+1)*byte], 16))
    return tuple(encryption_X)
def decrypt_encryption(str,sum=1,judge=2,mk=(0x01234567,0x89abcdef,0xfedcba98,0x76543210)):
    """
    该函数用于加解密
    :param str: 输入一个十六进制类型的字符串,最好len(str)=32个字符,用于加解密的数据
    :param sum: 加解密的次数
    :param judge: 0:加密，1:解密,2:加解密
    mk:加解密的密钥
    :return:
    """
    encryption=str
    s=SM4()
    if(type(mk)==str):
        mk=str_tuple(mk) #转化成元组
    k = 0  # 记录加密次数
    if(judge==0 or judge==2):
        print("初始加密明文:", k, encryption)
        print("加密次数 加密后的密文")
        for i in range(sum):
            encryption = s.encryption_main(str_tuple(encryption), mk)
            k = k + 1
            print(k, encryption, end="    ")
        print()
    k = 0  # 记录解密次数
    if(judge==1 or judge==2):
        print(".....................")
        print("初始解密明文:", k, encryption)
        print("解密次数 解密后的密文")
        for i in range(sum):
            encryption = s.decrypt_main(str_tuple(encryption), mk)
            k = k + 1
            print(k, encryption, end="    ")
        print()

if __name__=="__main__":
    X=(0x01234567,0x89abcdef,0xfedcba98,0x76543210)     #明文
    Y=(0x681edf34,0xd206965e,0x86b3e94f,0x536e4246)     #密文
    mk=(0x01234567,0x89abcdef,0xfedcba98,0x76543210)    #密钥
    s=SM4()
    print("明文:",s.decrypt_main(Y,mk))    #0123456789abcdeffedcba9876543210
    print("密文:",s.encryption_main(X,mk)) #681edf34d206965e86b3e94f536e4246
    print("##########################################")

    decrypt_encryption("0123456789abcdeffedcba9876543210", sum=5, judge=2)

    #以下程序将加密"0123456789abcdeffedcba9876543210"一百万次，时间较久，最终答案:
    #595298c7C6fd271f0402f804c33d3f66

    # encryption="0123456789abcdeffedcba9876543210"
    # for i in range(1000000):
    #     encryption = s.encryption_main(str_tuple(encryption), mk)
    # print(encryption)




