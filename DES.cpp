#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <math.h>
#include <bitset>
using namespace std;
#define ENCRYPT true
#define DECRYPT false
// Helper function prototypes 
void toUpperCase(string *text);
string permute(string k, vector<int> arr);
string hex2bin(string s);
string bin2hex(string s);
string shiftLeft(string k, int shifts, int bitsNumber);
string shiftRight(string k, int shifts, int bitsNumber);
string xor_string(string s1, string s2);
bool validate(string s);
void reenterInputs(string *plain, string *key);
int bin2dec(string s);
string dec2bin(int n);
string binary4bit(string b);
string sboxOp(string s_48);
void round(int roundNumber, string *plainLeft_32b, string *plainRight_32b, string *permKeyLeft_28b, string *permKeyRight_28b, bool isEncrypt);

// The function that Encrypt and Decrypt using DES
string DES_Encrypt_Decrypt(string plain, string key, bool isEncrypt);

const vector<int> initial_perm = {58, 50, 42, 34, 26, 18, 10, 2,
                                  60, 52, 44, 36, 28, 20, 12, 4,
                                  62, 54, 46, 38, 30, 22, 14, 6,
                                  64, 56, 48, 40, 32, 24, 16, 8,
                                  57, 49, 41, 33, 25, 17, 9, 1,
                                  59, 51, 43, 35, 27, 19, 11, 3,
                                  61, 53, 45, 37, 29, 21, 13, 5,
                                  63, 55, 47, 39, 31, 23, 15, 7};
// Expansion permutation Table
const vector<int> expansionPermutation = {32, 1, 2, 3, 4, 5, 4, 5,
                                          6, 7, 8, 9, 8, 9, 10, 11,
                                          12, 13, 12, 13, 14, 15, 16, 17,
                                          16, 17, 18, 19, 20, 21, 20, 21,
                                          22, 23, 24, 25, 24, 25, 26, 27,
                                          28, 29, 28, 29, 30, 31, 32, 1};
// S-box Table
const vector<vector<vector<int>>> sbox = {
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},

    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},

    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},

    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};
// Straight Permutation Table
const vector<int> permutation = {16, 7, 20, 21,
                                 29, 12, 28, 17,
                                 1, 15, 23, 26,
                                 5, 18, 31, 10,
                                 2, 8, 24, 14,
                                 32, 27, 3, 9,
                                 19, 13, 30, 6,
                                 22, 11, 4, 25};

const vector<int> permutatedChoice1 = {57, 49, 41, 33, 25, 17, 9,
                                       1, 58, 50, 42, 34, 26, 18,
                                       10, 2, 59, 51, 43, 35, 27,
                                       19, 11, 3, 60, 52, 44, 36,
                                       63, 55, 47, 39, 31, 23, 15,
                                       7, 62, 54, 46, 38, 30, 22,
                                       14, 6, 61, 53, 45, 37, 29,
                                       21, 13, 5, 28, 20, 12, 4};

const vector<int> permutedChoice2 = {14, 17, 11, 24, 1, 5,
                                     3, 28, 15, 6, 21, 10,
                                     23, 19, 12, 4, 26, 8,
                                     16, 7, 27, 20, 13, 2,
                                     41, 52, 31, 37, 47, 55,
                                     30, 40, 51, 45, 33, 48,
                                     44, 49, 39, 56, 34, 53,
                                     46, 42, 50, 36, 29, 32};
const int shiftTable[] = {1, 1, 2, 2, 2, 2, 2, 2,
                          1, 2, 2, 2, 2, 2, 2, 1};
const int inverseShiftTable[]{0, 1, 2, 2, 2, 2, 2, 2,
                              1, 2, 2, 2, 2, 2, 2, 1};
// inverse Initial Permutation Table
const vector<int> inverseInitPermutation = {40, 8, 48, 16, 56, 24, 64, 32,
                                            39, 7, 47, 15, 55, 23, 63, 31,
                                            38, 6, 46, 14, 54, 22, 62, 30,
                                            37, 5, 45, 13, 53, 21, 61, 29,
                                            36, 4, 44, 12, 52, 20, 60, 28,
                                            35, 3, 43, 11, 51, 19, 59, 27,
                                            34, 2, 42, 10, 50, 18, 58, 26,
                                            33, 1, 41, 9, 49, 17, 57, 25};
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
