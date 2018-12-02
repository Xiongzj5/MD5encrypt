#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>
#include "MD5-Encrypt.h"
using namespace std;

string MD5::encrypt(string plaintext){
    tempA = A;
    tempB = B;
    tempC = C;
    tempD = D;
    unsigned int* strByte = fillData(plaintext); // here we can get (N+1)*512 bits, equle to (N+1)*64 bytes
    // 先把(N+1)*512 bits 按照 512 bits一组来进行分组（也就是16个int一组）
    // 然后每一分组被划分为16个32位子分组
    // 一个int是4个字节，32个bit(位)
    // 所以说一个子分组被划分成16个32位子分组也就是16个int, 为16组
    for(unsigned int i = 0;i < strlength / 16; i++){ // 首先是按照512 bits来分组
        unsigned int num[16]; // 代表一个分组的16个int, 我们把这个分组的16个int给取出来
        for(unsigned int j = 0;j < 16;j++){
            num[j] = strByte[i * 16 + j]; // i * 16 代表第几组， j 代表该组中的第几位
        }
        mainLoop(num);
    }
    ciphertext += changeHex(tempA);
    ciphertext += changeHex(tempB);
    ciphertext += changeHex(tempC);
    ciphertext += changeHex(tempD);
    return ciphertext;
}
unsigned int* MD5::fillData(string initialtext){
    // 首先我们需要确定(N+1) * 512 bits 里的这个N的值
    // 假设 m 是补位的位数， 那么原字符串加上源字符串的的64位表达可以表示为： (N + 1) * 512 - m
    // m 是小于512的一个数
    // [(N + 1) * 512 - m] / 512 = N
    // 我们这里使用字节运算，不用位来进行运算
    unsigned int num = ((initialtext.length() + 8) / 64) + 1; // 这里num = N + 1
    unsigned int* strByte =  new unsigned int[num * 16];
    strlength = num * 16; // 这里我们可以确认填充后的字符串的int的位数
    for(unsigned int i = 0; i < num * 16; i++) { // 先全部设置为0
        strByte[i] = 0;
    }
    // 因为strByte是unsigned int*的， 一个unsigned int 四个字节
    // 而initialtext是一个字符串，一个字符是一个字节，所以一个unsigned int存四个字符
    // i >> 2代表的是 i / 4， 也就是找到字符所对应的unsigned int
    // (i % 4) * 8 就是找到这个字符在unsigned int中所对应的那个字节
    // 然后移位使得该字节移动到对应的字节上面去
    for(unsigned int i = 0; i < initialtext.length(); i++){
        strByte[i >> 2] |= (initialtext[i]) << ((i % 4) * 8);
    }
    // 0x80是二进制的10000000，我们在原来字符串的后面接上一个10000000
    // 至于说后面还要跟多少个0，这我们就不用担心了
    // 因为前面我们在初始化strByte的时候，就已经决定了总长度并将每一位都初始化为0了
    // 所以我们只需要将该赋值的位赋值，其余的位就不需要我们管了
    strByte[initialtext.length() >> 2] |= 0x80 << (((initialtext.length() % 4)) * 8);
    // 这里我们需要在填充字符串的末尾加上原字符串的长度的64位表达， 所以 * 8表示了位的长度
    // 这里只使用了32位，所以可能还存在一些问题，以后再说
    strByte[num * 16 - 2] = initialtext.length() * 8;
    return strByte;
}

void MD5::mainLoop(unsigned int M[]){
    unsigned a = tempA;
    unsigned b = tempB;
    unsigned c = tempC;
    unsigned d = tempD;
    /*
    FF(a,b,c,d,Mj,s,ti)表示a=b+((a+F(b,c,d)+Mj+ti)<<<s)
    GG(a,b,c,d,Mj,s,ti)表示a=b+((a+G(b,c,d)+Mj+ti)<<<s)
    HH(a,b,c,d,Mj,s,ti)表示a=b+((a+H(b,c,d)+Mj+ti)<<<s)
    II(a,b,c,d,Mj,s,ti)表示a=b+((a+I(b,c,d)+Mj+ti)<<<s) */
     /* Round 1 */
    FF (a, b, c, d, M[0], s11, 0xd76aa478);
    FF (d, a, b, c, M[1], s12, 0xe8c7b756);
    FF (c, d, a, b, M[2], s13, 0x242070db);
    FF (b, c, d, a, M[3], s14, 0xc1bdceee);
    FF (a, b, c, d, M[4], s11, 0xf57c0faf);
    FF (d, a, b, c, M[5], s12, 0x4787c62a);
    FF (c, d, a, b, M[6], s13, 0xa8304613);
    FF (b, c, d, a, M[7], s14, 0xfd469501);
    FF (a, b, c, d, M[8], s11, 0x698098d8);
    FF (d, a, b, c, M[9], s12, 0x8b44f7af);
    FF (c, d, a, b, M[10], s13, 0xffff5bb1);
    FF (b, c, d, a, M[11], s14, 0x895cd7be);
    FF (a, b, c, d, M[12], s11, 0x6b901122);
    FF (d, a, b, c, M[13], s12, 0xfd987193);
    FF (c, d, a, b, M[14], s13, 0xa679438e);
    FF (b, c, d, a, M[15], s14, 0x49b40821);

    /* Round 2 */
    GG (a, b, c, d, M[ 1], s21, 0xf61e2562);
    GG (d, a, b, c, M[ 6], s22, 0xc040b340);
    GG (c, d, a, b, M[11], s23, 0x265e5a51);
    GG (b, c, d, a, M[ 0], s24, 0xe9b6c7aa);
    GG (a, b, c, d, M[ 5], s21, 0xd62f105d);
    GG (d, a, b, c, M[10], s22,  0x2441453);
    GG (c, d, a, b, M[15], s23, 0xd8a1e681);
    GG (b, c, d, a, M[ 4], s24, 0xe7d3fbc8);
    GG (a, b, c, d, M[ 9], s21, 0x21e1cde6);
    GG (d, a, b, c, M[14], s22, 0xc33707d6);
    GG (c, d, a, b, M[ 3], s23, 0xf4d50d87);
    GG (b, c, d, a, M[ 8], s24, 0x455a14ed);
    GG (a, b, c, d, M[13], s21, 0xa9e3e905);
    GG (d, a, b, c, M[ 2], s22, 0xfcefa3f8);
    GG (c, d, a, b, M[ 7], s23, 0x676f02d9);
    GG (b, c, d, a, M[12], s24, 0x8d2a4c8a);

    /* Round 3 */
    HH (a, b, c, d, M[ 5], s31, 0xfffa3942);
    HH (d, a, b, c, M[ 8], s32, 0x8771f681);
    HH (c, d, a, b, M[11], s33, 0x6d9d6122);
    HH (b, c, d, a, M[14], s34, 0xfde5380c);
    HH (a, b, c, d, M[ 1], s31, 0xa4beea44);
    HH (d, a, b, c, M[ 4], s32, 0x4bdecfa9);
    HH (c, d, a, b, M[ 7], s33, 0xf6bb4b60);
    HH (b, c, d, a, M[10], s34, 0xbebfbc70);
    HH (a, b, c, d, M[13], s31, 0x289b7ec6);
    HH (d, a, b, c, M[ 0], s32, 0xeaa127fa);
    HH (c, d, a, b, M[ 3], s33, 0xd4ef3085);
    HH (b, c, d, a, M[ 6], s34,  0x4881d05);
    HH (a, b, c, d, M[ 9], s31, 0xd9d4d039);
    HH (d, a, b, c, M[12], s32, 0xe6db99e5);
    HH (c, d, a, b, M[15], s33, 0x1fa27cf8);
    HH (b, c, d, a, M[ 2], s34, 0xc4ac5665);

    /* Round 4 */
    II (a, b, c, d, M[ 0], s41, 0xf4292244);
    II (d, a, b, c, M[ 7], s42, 0x432aff97);
    II (c, d, a, b, M[14], s43, 0xab9423a7);
    II (b, c, d, a, M[ 5], s44, 0xfc93a039);
    II (a, b, c, d, M[12], s41, 0x655b59c3);
    II (d, a, b, c, M[ 3], s42, 0x8f0ccc92);
    II (c, d, a, b, M[10], s43, 0xffeff47d);
    II (b, c, d, a, M[ 1], s44, 0x85845dd1);
    II (a, b, c, d, M[ 8], s41, 0x6fa87e4f);
    II (d, a, b, c, M[15], s42, 0xfe2ce6e0);
    II (c, d, a, b, M[ 6], s43, 0xa3014314);
    II (b, c, d, a, M[13], s44, 0x4e0811a1);
    II (a, b, c, d, M[ 4], s41, 0xf7537e82);
    II (d, a, b, c, M[11], s42, 0xbd3af235);
    II (c, d, a, b, M[ 2], s43, 0x2ad7d2bb);
    II (b, c, d, a, M[ 9], s44, 0xeb86d391);
    tempA = a + tempA;
    tempB = b + tempB;
    tempC = c + tempC;
    tempD = d + tempD;
}
//转换为16进制数 
string MD5::changeHex(long number){
    string str;
    int temp;
    while(number != 0){
        temp = number % 16;
        number /= 16;
        str += str16[temp];
    }
    string reverseStr(str.rbegin(), str.rend());  // u can get 4d1, and correct result is d1040000
    //cout << "reverse: " << reverseStr << endl;
    string result = "";
    string temp1;
    string temp2;
    string temp3;
    string temp4;
    for(int i=0;i<8;++i){
        if(i < 8-reverseStr.length()){
            result += "0";
        }
        else {
            result += reverseStr[i+reverseStr.length()-8];
        }
    }
    // 000004d1
    temp1 += result.substr(0,2); // 00
    temp2 += result.substr(2,2); // 00
    temp3 += result.substr(4,2); // 04
    temp4 += result.substr(6,2); // d1
    string changeResult = temp4 + temp3 + temp2 + temp1;
    //cout << "result is: " << result << endl;
    return changeResult;
}
