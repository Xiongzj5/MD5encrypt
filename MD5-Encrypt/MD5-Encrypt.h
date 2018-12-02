#ifndef MD5_H
#define WEBSECURE_H
using namespace std;
#define shift(x, n) (((x) << (n)) | ((x) >> (32-(n))))//右移的时候，高位一定要补零，而不是补充符号位
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))    
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
/* Parameters of MD5. */
#define s11 7
#define s12 12
#define s13 17
#define s14 22
#define s21 5
#define s22 9
#define s23 14
#define s24 20
#define s31 4
#define s32 11
#define s33 16
#define s34 23
#define s41 6
#define s42 10
#define s43 15
#define s44 21
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476
//#define FF(a,b,c,d,Mj,s,ti) a=b+((a+F(b,c,d)+Mj+ti)<<<s)
#define FF(a, b, c, d, x, s, ac) { \
  (a) += F ((b), (c), (d)) + (x) + ac; \
  (a) = shift ((a), (s)); \
  (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
  (a) += G ((b), (c), (d)) + (x) + ac; \
  (a) = shift ((a), (s)); \
  (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
  (a) += H ((b), (c), (d)) + (x) + ac; \
  (a) = shift ((a), (s)); \
  (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
  (a) += I ((b), (c), (d)) + (x) + ac; \
  (a) = shift ((a), (s)); \
  (a) += (b); \
}
#include <string>

class MD5{
    public:
        string ciphertext = "";
        string encrypt(std::string plaintext);
    //private:
        // strByte的长度
        unsigned int strlength;
        // 四个临时变量
        unsigned int tempA;
        unsigned int tempB;
        unsigned int tempC;
        unsigned int tempD;
        const char str16[17] = "0123456789abcdef";
         /*
	  *填充函数
	  *处理后应满足bits≡448(mod512),字节就是bytes≡56（mode64)
	  *填充方式为先加一个1,其它位补零
	  *最后加上64位的原来长度
	  */
        unsigned int* fillData(string initialtext);

        void mainLoop(unsigned int M[]);
        //转换为16进制数 
        string changeHex(int number);
};

#endif