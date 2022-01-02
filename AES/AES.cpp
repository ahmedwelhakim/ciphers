#define _CRT_SECURE_NO_WARNINGS
#include "AES.h"

using namespace std;


int main()
{
    cout << "Enter the key 32 element in Hex:" << endl;
    string key;
    cin >> key;
    cout << "Enter the plain text 32 element in Hex:" << endl;
    string plain;
    cin >> plain;
    toUpperCase(&plain);
    toUpperCase(&key);
    string enc = AES_Encrypt(plain, key);
    cout << "Encrypt: ";
    printHexArray(stringToCharArray(enc), 16);
    string dec = AES_Decrypt(hexToString(enc), key);
    cout << "Decrypt: ";
    printHexArray(stringToCharArray(dec), 16);
    return 0;
}

string AES_Encrypt(string plainText, string key)
{

    unsigned int len;

    unsigned char* enc = encryptECB(readHexString(plainText), 32, readHexString(key), len);
    return charArrayToString(enc, 32);
}

string AES_Decrypt(string cipher, string key)
{
    unsigned char* dec = decryptECB(readHexString(cipher), 32, readHexString(key));
    return charArrayToString(dec, 32);
}

void subBytes(unsigned char** state)
{
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            t = state[i][j];
            state[i][j] = S_Box[t / 16][t % 16];
        }
    }
}
void shiftRow(unsigned char** state, int i, int n) 
{
    unsigned char tmp[4];
    for (int j = 0; j < 4; j++)
    {
        tmp[j] = state[i][(j + n) % 4];
    }
    memcpy(state[i], tmp, 4 * sizeof(unsigned char));
}
void shiftRows(unsigned char** state)
{
    shiftRow(state, 1, 1);
    shiftRow(state, 2, 2);
    shiftRow(state, 3, 3);
}
void mixColumns(unsigned char** state)
{
    unsigned char temp_state[4][4];

    for (size_t i = 0; i < 4; ++i)
    {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t k = 0; k < 4; ++k)
        {
            for (size_t j = 0; j < 4; ++j)
            {
                if (CMDS[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i)
    {
        memcpy(state[i], temp_state[i], 4);
    }
}
void addRoundKey(unsigned char** state, unsigned char* key)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}
void subWord(unsigned char* a)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        a[i] = S_Box[a[i] / 16][a[i] % 16];
    }
}
void rotWord(unsigned char* a)
{
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void xorWords(unsigned char* a, unsigned char* b, unsigned char* c)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void Rcon(unsigned char* a, int n)
{
    int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++)
    {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}
unsigned char xtime(unsigned char b)    // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}
void keyExpansion(unsigned char key[], unsigned char w[])
{
    unsigned char* temp = new unsigned char[4];
    unsigned char* rcon = new unsigned char[4];

    int i = 0;
    while (i < 4 * Nk)
    {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1))
    {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0)
        {
            rotWord(temp);
            subWord(temp);
            Rcon(rcon, i / (Nk * 4));
            xorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4)
        {
            subWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }

    delete[]rcon;
    delete[]temp;

}


void invSubBytes(unsigned char** state)
{
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = Inv_S_Box[t / 16][t % 16];
        }
    }
}



void invMixColumns(unsigned char** state)
{
    unsigned char temp_state[4][4];

    for (size_t i = 0; i < 4; ++i)
    {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t k = 0; k < 4; ++k)
        {
            for (size_t j = 0; j < 4; ++j)
            {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i)
    {
        memcpy(state[i], temp_state[i], 4);
    }
}

void invShiftRows(unsigned char** state)
{
    shiftRow(state, 1, Nb - 1);
    shiftRow(state, 2, Nb - 2);
    shiftRow(state, 3, Nb - 3);
}

void xorBlocks(unsigned char* a, unsigned char* b, unsigned char* c, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void printHexArray(unsigned char a[], unsigned int n)
{
    for (unsigned int i = 0; i < n; i++) {
        printf("%02X", a[i]);
    }
    printf("\n");
}

void printHexVector(vector<unsigned char> a)
{
    for (unsigned int i = 0; i < a.size(); i++) {
        printf("%02x ", a[i]);
    }
}
void encrypt(unsigned char in[], unsigned char out[], unsigned  char* roundKeys)
{
    unsigned char** state = new unsigned char* [4];
    state[0] = new unsigned  char[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++)
    {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = in[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
}
unsigned char* encryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int& outLen)
{
  
    outLen = getPaddingLength(inLen);
    unsigned char* alignIn = paddingNulls(in, inLen, outLen);
    unsigned char* out = new unsigned char[outLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    keyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < outLen; i += blockBytesLen)
    {
        encrypt(in + i, out + i, roundKeys);
    }

    delete[] alignIn;
    delete[] roundKeys;
    free(in);
    free(key);

    return out;
}

unsigned char* stringToCharArray(string s)
{
    int size = s.size();
    unsigned char* arr=(unsigned char *)malloc (33*sizeof(unsigned char));
    const char *c = s.c_str();
    strcpy((char*)arr, s.c_str());
    arr[32] = '\0';
    return arr;
}
string charArrayToString(unsigned char arr[], int size)
{
    string s = "";
    for (size_t i = 0; i < size; i++)
    {
        s += '0';
    }
    for (size_t i = 0; i < size; i++)
    {
        s[i] = arr[i];
    }

    return s;

}

unsigned char* paddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
    unsigned char* alignIn = new unsigned char[alignLen];
    memcpy(alignIn, in, inLen);
    memset(alignIn + inLen, 0x00, alignLen - inLen);
    return alignIn;
}

unsigned int getPaddingLength(unsigned int len)
{
    unsigned int lengthWithPadding = (len / blockBytesLen);
    if (len % blockBytesLen) {
        lengthWithPadding++;
    }

    lengthWithPadding *= blockBytesLen;

    return lengthWithPadding;
}
unsigned char* readHexString(string s)
{

    unsigned char* arr = (unsigned char*)malloc(16 * sizeof(unsigned char));
    unsigned char a, b;
    for (size_t i = 0; i < s.size(); i += 2)
    {
        a = charToHex(s[i]);
        b = charToHex(s[i + 1]);
        arr[(i / 2)] = (a << 4) + b;

    }
    return arr;
}
string hexToString(string s)
{
    string out = "";
    for (size_t i = 0; i < s.size()/2; i++)
    {
        out += hexToChar(s[i] >> 4);
        out += hexToChar(s[i]);
       
    }
    return out;
}
unsigned char charToHex(char s)
{
    unsigned char out;

    switch (s)
    {
    case '0':
        out = 0x0;
        break;
    case '1':
        out = 0x1;
        break;
    case '2':
        out = 0x2;
        break;
    case '3':
        out = 0x3;
        break;
    case '4':
        out = 0x4;
        break;
    case '5':
        out = 0x5;
        break;
    case '6':
        out = 0x6;
        break;
    case '7':
        out = 0x7;
        break;
    case '8':
        out = 0x8;
        break;
    case '9':
        out = 0x9;
        break;
    case 'A':
        out = 0xA;
        break;
    case 'B':
        out = 0xB;
        break;
    case 'C':
        out = 0xC;
        break;
    case 'D':
        out = 0xD;
        break;
    case 'E':
        out = 0xE;
        break;
    case 'F':
        out = 0xF;
        break;
    default:
        out = -1;
        break;
    }
    return out;
}

unsigned char hexToChar(char s)
{
    unsigned char out;

    switch (s&0xf)
    {
    case 0x0 :
        out = '0';
        break;
    case 0x1:
        out = '1';
        break;
    case 0x2:
        out = '2';
        break;
    case 0x3:
        out = '3';
        break;
    case 0x4:
        out = '4';
        break;
    case 0x5:
        out = '5';
        break;
    case 0x6:
        out = '6';
        break;
    case 0x7:
        out = '7';
        break;
    case 0x8:
        out = '8';
        break;
    case 0x9:
        out = '9';
        break;
    case 0xA:
        out = 'A';
        break;
    case 0xB:
        out = 'B';
        break;
    case 0xC:
        out = 'C';
        break;
    case 0xD:
        out = 'D';
        break;
    case 0xE:
        out = 'E';
        break;
    case 0xF:
        out = 'F';
        break;
    default:
        out = 0;
        break;
    }
    return out;
}
unsigned char* decryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[])
{
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    keyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen)
    {
        decrypt(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}
void decrypt(unsigned char in[], unsigned char out[], unsigned  char* roundKeys)
{
    unsigned char** state = new unsigned char* [4];
    state[0] = new unsigned  char[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++)
    {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    addRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--)
    {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, roundKeys + round * 4 * Nb);
        invMixColumns(state);
    }

    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
}
void toUpperCase(string* text)
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