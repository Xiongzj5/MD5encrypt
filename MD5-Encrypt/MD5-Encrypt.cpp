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
    unsigned int* fillResult = fillData(plaintext); // here we can get (N+1)*512 bits, equle to (N+1)*64 bytes
    // 先把(N+1)*512 bits 按照 512 bits一组来进行分组（也就是16个int一组）
    // 然后每一分组被划分为16个32位子分组
    // 一个int是4个字节，32个bit(位)
    // 所以说一个子分组被划分成16个32位子分组也就是16个int, 为16组
    for(int i = 0;i < strlength / 16; ++i){ // 首先是按照512 bits来分组
        unsigned int num[16]; // 代表一个分组的16个int, 我们把这个分组的16个int给取出来
        for(int j = 0;j < 16;++j){
            num[j] = fillResult[i * 16 + j]; // i * 16 代表第几组， j 代表该组中的第几位
        }
        mainLoop(num);
        ciphertext += changeHex(tempA) + changeHex(tempB) + changeHex(C) + changeHex(D);
    }
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
    for(int i = 0; i < num * 16; ++i) { // 先全部设置为0
        strByte[i] = 0;
    }
    for(int i=0; i < initialtext.length(); ++i){
        strByte[i >> 2] |= (initialtext[i]) << 
    }
    return strByte;
}

void MD5::mainLoop(unsigned int M[]){

}
//转换为16进制数 
string MD5::changeHex(int number){
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
