#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <math.h>
#include <bitset>
#include"DES.h"
using namespace std;

int main()
{
    string pt, key;
    int n;
    cout << "Enter key:" << endl;
    cin >> key;
    cout << "Enter Plain text" << endl;
    cin >> pt;
    cout << "Enter number of encryprions" << endl;
    cin >> n;
    string enc = pt;
    for (size_t i = 0; i < n; i++)
    {
        enc = DES_Encrypt_Decrypt(enc, key, ENCRYPT);
    }

    cout << "Encrypt:" << enc << endl;
    string dec = enc;
    for (size_t i = 0; i < n; i++)
    {
        dec = DES_Encrypt_Decrypt(dec, key, DECRYPT);
    }

    cout << "Decrypt:" << dec << endl;

    return 0;
}
string DES_Encrypt_Decrypt(string plain, string key, bool isEncrypt)
{
DES_BEGIN:
    bool valid = false;
    // validate the inputs are 16 hex character
    valid = validate(plain) && validate(key);
    if (valid == false)
    {
        cout << "Incorrect inputs" << endl;
        reenterInputs(&plain, &key);
        goto DES_BEGIN;
    }
    // first permute the initial permutation to the plain text
    string plain_64bin = permute(hex2bin(plain), initial_perm);
    // output plain text 64 bit in binary

    string pLeft_32bin = plain_64bin.substr(0, 32);   // 32-bit
    string pRight_32bin = plain_64bin.substr(32, 64); // 32-bit

    string key_64bin = hex2bin(key); // 64-bit

    // permute the key to output 56-bit
    string permKey_56bin = permute(key_64bin, permutatedChoice1);
    string kLeft_28bin = permKey_56bin.substr(0, permKey_56bin.size() / 2);                     // 28-bit
    string kRight_28bin = permKey_56bin.substr(permKey_56bin.size() / 2, permKey_56bin.size()); // 28-bit

    // Execute the 16 round of DES
    for (size_t i = 0; i < 16; i++)
    {
        round(i, &pLeft_32bin, &pRight_32bin, &kLeft_28bin, &kRight_28bin, isEncrypt);
    }
    // swapping left with right
    string temp = pLeft_32bin;
    pLeft_32bin = pRight_32bin;
    pRight_32bin = temp;

    // Inverse Initial permutaion
    plain_64bin = pLeft_32bin + pRight_32bin;
    plain_64bin = permute(plain_64bin, inverseInitPermutation);

    return bin2hex(plain_64bin);
}
string permute(string k, vector<int> arr)
{
    string per = "";
    for (int i = 0; i < arr.size(); i++)
    {
        per += k[arr[i] - 1];
    }
    return per;
}
string sboxOp(string s_48)
{
    string result_32;
    for (size_t i = 0; i < 8; i++)
    {
        string row_bin = "";
        row_bin += s_48[6 * i];
        row_bin += s_48[6 * i + 5];

        int row = bin2dec(row_bin);
        string col_bin = "";
        col_bin += s_48[6 * i + 1];
        col_bin += s_48[6 * i + 2];
        col_bin += s_48[6 * i + 3];
        col_bin += s_48[6 * i + 4];
        int col = bin2dec(col_bin);
        result_32 += binary4bit(dec2bin(sbox[i][row][col]));
    }
    return result_32;
}
void round(int roundNumber, string *plainLeft_32b, string *plainRight_32b, string *permKeyLeft_28b, string *permKeyRight_28b, bool isEncrypt)
{
    if (isEncrypt == ENCRYPT)
    {
        // key is left shifted
        (*permKeyLeft_28b) = shiftLeft((*permKeyLeft_28b), shiftTable[roundNumber], 28);
        (*permKeyRight_28b) = shiftLeft((*permKeyRight_28b), shiftTable[roundNumber], 28);
    }
    else
    {
        // key is left shifted
        (*permKeyLeft_28b) = shiftRight((*permKeyLeft_28b), inverseShiftTable[roundNumber], 28);
        (*permKeyRight_28b) = shiftRight((*permKeyRight_28b), inverseShiftTable[roundNumber], 28);
    }

    string key_56 = (*permKeyLeft_28b) + (*permKeyRight_28b);
    string key_48 = permute(key_56, permutedChoice2);

    string plainRight_32b_old = *plainRight_32b;

    // right plain enter to expansion table
    string plainRight_48 = permute(*plainRight_32b, expansionPermutation);
    plainRight_48 = xor_string(plainRight_48, key_48);

    // s-box
    (*plainRight_32b) = sboxOp(plainRight_48);
    // permutaion P
    (*plainRight_32b) = permute(*plainRight_32b, permutation);
    // XOR with left side
    *plainRight_32b = xor_string(*plainLeft_32b, *plainRight_32b);
    *plainLeft_32b = plainRight_32b_old;
}
string hex2bin(string s)
{
    toUpperCase(&s);
    map<char, string> m;
    m['0'] = "0000";
    m['1'] = "0001";
    m['2'] = "0010";
    m['3'] = "0011";
    m['4'] = "0100";
    m['5'] = "0101";
    m['6'] = "0110";
    m['7'] = "0111";
    m['8'] = "1000";
    m['9'] = "1001";
    m['A'] = "1010";
    m['B'] = "1011";
    m['C'] = "1100";
    m['D'] = "1101";
    m['E'] = "1110";
    m['F'] = "1111";
    string result = "";
    for (size_t i = 0; i < s.size(); i++)
    {
        result += m[s[i]];
    }
    return result;
}
string bin2hex(string s)
{
    map<string, char> m;
    m["0000"] = '0';
    m["0001"] = '1';
    m["0010"] = '2';
    m["0011"] = '3';
    m["0100"] = '4';
    m["0101"] = '5';
    m["0110"] = '6';
    m["0111"] = '7';
    m["1000"] = '8';
    m["1001"] = '9';
    m["1010"] = 'A';
    m["1011"] = 'B';
    m["1100"] = 'C';
    m["1101"] = 'D';
    m["1110"] = 'E';
    m["1111"] = 'F';
    string result = "";
    for (size_t i = 0; i < s.size(); i += 4)
    {
        string index = "";
        index += s[i];
        index += s[i + 1];
        index += s[i + 2];
        index += s[i + 3];
        result += m[index];
    }
    return result;
}
string shiftLeft(string k, int shifts, int bitsNumber)
{
    string s = "";
    for (int i = 0; i < shifts; i++)
    {
        for (int j = 1; j < bitsNumber; j++)
        {
            s += k[j];
        }
        s += k[0];
        k = s;
        s = "";
    }
    return k;
}
string shiftRight(string k, int shifts, int bitsNumber)
{
    string s = "";
    for (int i = 0; i < shifts; i++)
    {
        s += k[bitsNumber - 1];
        for (int j = 0; j < bitsNumber - 1; j++)
        {
            s += k[j];
        }

        k = s;
        s = "";
    }
    return k;
}
string xor_string(string s1, string s2)
{
    string ans = "";
    for (int i = 0; i < s1.size(); i++)
    {
        if (s1[i] == s2[i])
        {
            ans += "0";
        }
        else
        {
            ans += "1";
        }
    }
    return ans;
}
bool validate(string s)
{
    string s_upper = s;
    toUpperCase(&s_upper);
    if (s_upper.size() > 16)
    {
        return false;
    }
    for (size_t i = 0; i < s_upper.size(); i++)
    {
        if (!((s_upper[i] >= 'A' && s_upper[i] <= 'Z') || (s_upper[i] >= '0' && s_upper[i] <= '9')))
            return false;
        else
            return true;
    }
}
void reenterInputs(string *plain, string *key)
{
    cout << "please reenter plain text in hexadecimal and size = 16" << endl;
    cin >> (*plain);
    cout << "please reenter key in hexadecimal and size = 16" << endl;
    cin >> (*key);
}
int bin2dec(string s)
{
    int res = 0;
    for (size_t i = 0; i < s.size(); i++)
    {
        res += ((s[s.size() - 1 - i] - '0') * pow(2, i));
    }
    return res;
}
string dec2bin(int n)
{
    // finding the binary form of the number and
    // converting it to string.
    string s = bitset<64>(n).to_string();

    // Finding the first occurrence of "1"
    // to strip off the leading zeroes.
    const auto loc1 = s.find('1');

    if (loc1 != string::npos)
        return s.substr(loc1);

    return "0";
}
string binary4bit(string b)
{
    string res = "";
    if (b.size() < 4)
    {
        for (size_t i = 0; i < 4 - b.size(); i++)
        {
            res += "0";
        }
        res += b;
    }
    else
    {
        for (size_t i = 0; i < 4; i++)
        {
            res += b[i + (b.size() - 4)];
        }
    }
    return res;
}
void toUpperCase(string *text)
{
    for (size_t i = 0; i < (*(text)).size(); i++)
    {
        // Make all Upper case
        if (islower((*(text))[i]))
        {
            (*text)[i] = toupper((*text)[i]);
        }
    }
}
