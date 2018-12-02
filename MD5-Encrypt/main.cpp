#include <iostream>
#include <string>
#include <vector>
#include "MD5-Encrypt.h"
using namespace std;
int main(){
    MD5 obj1;
    string s;
    cout << "input your string" << endl;
    cin >> s;
    string result = obj1.encrypt(s);
    cout << "the result of encryption is：" << endl;
    cout << result << endl;
    return 0;
}