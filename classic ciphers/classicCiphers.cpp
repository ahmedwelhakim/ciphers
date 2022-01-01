#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include"classicCiphers.h"
using namespace std;

int main()
{
    // ------- 1 CEASAR CIPHER -------------------------------------------------------------------
    vector<string> ceaserPlainTexts = readFileToStrings("Input Files/Caesar/caesar_plain.txt");
    for (size_t i = 0; i < ceaserPlainTexts.size(); i++)
    {
        string cipher_3 = CeaserCipherEncrypt(ceaserPlainTexts[i], 3);
        string cipher_6 = CeaserCipherEncrypt(ceaserPlainTexts[i], 6);
        string cipher_12 = CeaserCipherEncrypt(ceaserPlainTexts[i], 12);
        if (i == 0)
        {
            saveTofile("outputs/Caesar/ceaser_cipher_3.txt", cipher_3);
            saveTofile("outputs/Caesar/ceaser_cipher_6.txt", cipher_6);
            saveTofile("outputs/Caesar/ceaser_cipher_12.txt", cipher_12);
        }
        else
        {
            appendTofile("outputs/Caesar/ceaser_cipher_3.txt", cipher_3);
            appendTofile("outputs/Caesar/ceaser_cipher_6.txt", cipher_6);
            appendTofile("outputs/Caesar/ceaser_cipher_12.txt", cipher_12);
        }
    }

    // ------- 2 PLAY FAIR CIPHER -------------------------------------------------------------------
    vector<string> playFairPlaintexts = readFileToStrings("Input Files/PlayFair/playfair_plain.txt");
    for (size_t i = 0; i < playFairPlaintexts.size(); i++)
    {
        string cipher_rats = PlayFairCipherEncrypt(playFairPlaintexts[i], "rats");
        string cipher_archangel = PlayFairCipherEncrypt(playFairPlaintexts[i], "archangel");
        if (i == 0)
        {
            saveTofile("outputs/PlayFair/playfair_cipher_rats.txt", cipher_rats);
            saveTofile("outputs/PlayFair/playfair_cipher_archangel.txt", cipher_archangel);
        }
        else
        {
            appendTofile("outputs/PlayFair/playfair_cipher_rats.txt", cipher_rats);
            appendTofile("outputs/PlayFair/playfair_cipher_archangel.txt", cipher_archangel);
        }
    }
    // -------- 3 HILL CIPHER -----------------------------------------------------------------------
    vector<vector<int>> key1 = {{5, 17},
                                {8, 3}};

    vector<vector<int>> key2 = {{2, 4, 12},
                                {9, 1, 6},
                                {7, 5, 3}};
    vector<string> hillPlaintexts_2x2 = readFileToStrings("Input Files/Hill/hill_plain_2x2.txt");
    vector<string> hillPlaintexts_3x3 = readFileToStrings("Input Files/Hill/hill_plain_3x3.txt");
    for (size_t i = 0; i < hillPlaintexts_2x2.size(); i++)
    {
        string hillCipher = HillCipherEncrypt(hillPlaintexts_2x2[i], key1);
        if (i == 0)
        {
            saveTofile("outputs/Hill/hill_cipher_2x2.txt", hillCipher);
        }
        else
        {
            appendTofile("outputs/Hill/hill_cipher_2x2.txt", hillCipher);
        }
    }
    for (size_t i = 0; i < hillPlaintexts_3x3.size(); i++)
    {
        string hillCipher = HillCipherEncrypt(hillPlaintexts_3x3[i], key2);
        if (i == 0)
        {
            saveTofile("outputs/Hill/hill_cipher_3x3.txt", hillCipher);
        }
        else
        {
            appendTofile("outputs/Hill/hill_cipher_3x3.txt", hillCipher);
        }
    }
    // -------- 4 VIGENERE CIPHER -----------------------------------------------------------------------
    vector<string> vigenerePlainTexts = readFileToStrings("Input Files/Vigenere/vigenere_plain.txt");
    for (size_t i = 0; i < vigenerePlainTexts.size(); i++)
    {
        string vCipher_pie_repeating = VigenerCipherEncrypt(vigenerePlainTexts[i], "pie", REPEATING_MODE);
        string vCipher_aether_auto = VigenerCipherEncrypt(vigenerePlainTexts[i], "aether", AUTO_MODE);

        if (i == 0)
        {
            saveTofile("outputs/Vigenere/vigenere_cipher_pie_repeating.txt", vCipher_pie_repeating);
            saveTofile("outputs/Vigenere/vigenere_cipher_aether_auto.txt", vCipher_aether_auto);
        }
        else
        {
            appendTofile("outputs/Vigenere/vigenere_cipher_pie_repeating.txt", vCipher_pie_repeating);
            appendTofile("outputs/Vigenere/vigenere_cipher_aether_auto.txt", vCipher_aether_auto);
        }
    }
    // -------- 5 VERNAM CIPHER -----------------------------------------------------------------------
    vector<string> vernamPlainTexts=readFileToStrings("Input Files/Vernam/vernam_plain.txt");
    for (size_t i = 0; i < vernamPlainTexts.size(); i++)
    {
        string vernam_cipher_SPARTANS=VernamCipherEncrypt(vernamPlainTexts[i],"SPARTANS");
        if (i == 0)
        {
            saveTofile("outputs/Vernam/vernam_cipher_SPARTANS.txt", vernam_cipher_SPARTANS);
        }
        else
        {
            appendTofile("outputs/Vernam/vernam_cipher_SPARTANS.txt", vernam_cipher_SPARTANS);
        }
    }
    
    return 0;
}

string CeaserCipherEncrypt(const string text, const int s)
{
    string result = "";

    for (int i = 0; i < text.length(); i++)
    {
        // Encrypt Uppercase letters
        if (isupper(text[i]))
        {
            result += char(int(text[i] + s - 65) % 26 + 65);
        }
        // Encrypt Lowercase letters
        else
        {
            result += char(int(text[i] + s - 97) % 26 + 97);
        }
    }

    return result;
}

string PlayFairCipherEncrypt(const string plainText, const string key)
{
    string result = plainText;
    string preparedKey = key;
    // prepare the plain text to be ciphered
    toLowerCase(&result);
    // remove spaces
    removeSpaces(&result);
    // if two letter in couple are the same put x between them
    for (size_t i = 0; i < result.size(); i++)
    {
        if (result[i] == result[i + 1] && i % 2 == 0)
        {
            result.insert(i + 1, "x");
        }
    }
    // if size not even insert x to last letter
    if (result.size() % 2 != 0)
    {
        result.insert(result.size(), "x");
    }

    // make key all lower case
    toLowerCase(&preparedKey);
    // letter frequency array
    int letterFrequencies[26] = {0};

    char matrix[5][5];

    prepareMatrixTable(preparedKey, letterFrequencies, matrix);
    // Now the matrix is initialized w need to search for letter position and
    // do the playfair encryption
    int searchedIndices[4];
    for (size_t i = 0; i < result.size(); i += 2)
    {
        search(matrix, result[i], result[i + 1], searchedIndices);
        if (searchedIndices[0] == searchedIndices[2])
        {
            result[i] = matrix[searchedIndices[0]][mod5(searchedIndices[1] + 1)];
            result[i + 1] = matrix[searchedIndices[0]][mod5(searchedIndices[3] + 1)];
        }
        else if (searchedIndices[1] == searchedIndices[3])
        {
            result[i] = matrix[mod5(searchedIndices[0] + 1)][searchedIndices[1]];
            result[i + 1] = matrix[mod5(searchedIndices[2] + 1)][searchedIndices[1]];
        }
        else
        {
            result[i] = matrix[searchedIndices[0]][searchedIndices[3]];
            result[i + 1] = matrix[searchedIndices[2]][searchedIndices[1]];
        }
    }

    return result;
}

string HillCipherEncrypt(const string plain, const vector<vector<int>> key)
{
    string plainText = plain;
    toLowerCase(&plainText);
    string cipher = "";
    for (size_t i = 0; i < plain.size(); i += key.size())
    {
        vector<vector<int>> m2;

        for (size_t j = 0; j < key.size(); j++)
        {
            vector<int> t;
            if (plainText[i + j] != 0)
            {
                t.push_back(plainText[i + j] - 'a');
            }
            else
            {
                // insert x's as padding
                t.push_back('x' - 'a');
            }

            m2.push_back(t);
        }
        vector<vector<int>> res = multiply(key, m2);
        for (size_t j = 0; j < res.size(); j++)
        {
            res[j][0] = mod26(res[j][0]);
        }
        for (size_t j = 0; j < res.size(); j++)
        {
            cipher += (char)(res[j][0] + 'a');
        }
    }
    toUpperCase(&cipher);
    return cipher;
}

string VigenerCipherEncrypt(const string plain, const string key, const bool mode)
{
    string plainText = plain;
    toLowerCase(&plainText);
    removeSpaces(&plainText);
    string keyFull = "";
    string cipher = "";
    if (mode == REPEATING_MODE)
    {
        for (size_t i = 0; i < plainText.size(); i++)
        { // repeating the key to the length of plain text
            keyFull += key[(i % key.size())];
        }
    }
    else if (mode == AUTO_MODE)
    {
        for (size_t i = 0; i < plainText.size(); i++)
        { // write the key once then complete from the plain text
            if (i < key.size())
            {
                keyFull += key[i];
            }
            else
            {
                keyFull += plainText[i - key.size()];
            }
        }
    }
    for (size_t i = 0; i < plainText.size(); i++)
    {
        cipher += mod26((plainText[i] - 'a') + (keyFull[i] - 'a')) + 'a';
    }

    return cipher;
}

string VernamCipherEncrypt(const string plain, const string key)
{
    // Vernam cipher one time padded implemented as in Cryptography and Network Security Sixth edition
    // number of characters are 27 the 27th is space
    string plainText = plain;
    string keyModified = key;
    string cipher = "";
    toUpperCase(&plainText);
    toUpperCase(&keyModified);
    for (size_t i = 0; i < plain.size(); i++)
    {
        int ciph;
        if (plainText[i] != ' ' && keyModified[i] != ' ')
        {
            ciph = (plainText[i] - 'A') + (keyModified[i] - 'A');
        }
        else if (plainText[i] == ' ' && keyModified[i] != ' ')
        {
            ciph = 26 + (keyModified[i] - 'A');
        }
        else if (plainText[i]!= ' '&& keyModified[i]==' ')
        {
            ciph=(plainText[i] - 'A')+26;
        }
        else{
            ciph=26+26;
        }
        while (ciph >= 27)
        {
            ciph -= 27;
        }

        if(ciph==26)
        {
            ciph=' '-'A';
        }                                
        cipher += ciph + 'A';
    }

    return cipher;
}
void removeSpaces(string *s)
{
    (*s).erase(remove_if((*s).begin(), (*s).end(), ::isspace), (*s).end());
}
vector<vector<int>> multiply(vector<vector<int>> m1, vector<vector<int>> m2)
{
    vector<vector<int>> result;
    // initialize result array with Zeros
    for (size_t i = 0; i < m1.size(); i++)
    {
        vector<int> v;
        result.push_back(v);
        for (size_t j = 0; j < m2[i].size(); j++)
        {
            result[i].push_back(0);
        }
    }
    for (size_t i = 0; i < m1.size(); i++)
    {
        for (size_t j = 0; j < m2[i].size(); j++)
        {
            for (size_t k = 0; k < m1[i].size(); k++)
            {
                result[i][j] += m1[i][k] * m2[k][j];
            }
        }
    }
    return result;
}
void toLowerCase(string *text)
{
    for (size_t i = 0; i < (*(text)).size(); i++)
    {
        // Make all lower case
        if (isupper((*(text))[i]))
        {
            (*text)[i] = tolower((*text)[i]);
        }
    }
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
void prepareMatrixTable(string preparedKey, int *letterFrequencies, char matrix[5][5])
{
    int loopCounter = 0;
    int alphabeticNumber = 0;
    // Initialize the matrix with the key and alphabetics
    for (size_t i = 0; i < 5; i++)
    {
        for (size_t j = 0; j < 5; j++)
        {
            if (loopCounter < preparedKey.size())
            {
            LETTER_FREQUENCY:
                if (letterFrequencies[preparedKey[loopCounter] - 97] < 1)
                {
                    if (preparedKey[loopCounter] != 'j')
                    {
                        matrix[i][j] = preparedKey[loopCounter];
                        letterFrequencies[preparedKey[loopCounter] - 97]++;
                        loopCounter++;
                    }
                    else
                    {
                        if (letterFrequencies['i' - 97] < 1)
                        {
                            matrix[i][j] = 'i';
                            letterFrequencies['i' - 97]++;
                            loopCounter++;
                            continue;
                        }
                        loopCounter++;
                        goto LETTER_FREQUENCY;
                    }
                }
                else
                {
                    while (letterFrequencies[preparedKey[loopCounter] - 97] >= 1 && loopCounter < preparedKey.size())
                    {
                        loopCounter++;
                    }
                    if (loopCounter < preparedKey.size())
                    {
                        matrix[i][j] = preparedKey[loopCounter];
                        letterFrequencies[preparedKey[loopCounter] - 97]++;
                    }
                    else
                    {
                        goto A;
                    }
                }
            }
            else // the key is written in the matrix
            // the matrix should be filled with the remain alphabetic in alphabetic order
            {
            A:
                while (letterFrequencies[alphabeticNumber] > 0 || (alphabeticNumber + 97) == 'j')
                {
                    alphabeticNumber++;
                }
                matrix[i][j] = (char)(alphabeticNumber + 97);
                alphabeticNumber++;
            }
        }
    }
}
void search(char keyT[5][5], char a, char b, int arr[])
{
    int i, j;

    if (a == 'j')
        a = 'i';
    else if (b == 'j')
        b = 'i';

    for (i = 0; i < 5; i++)
    {

        for (j = 0; j < 5; j++)
        {

            if (keyT[i][j] == a)
            {
                arr[0] = i;
                arr[1] = j;
            }
            else if (keyT[i][j] == b)
            {
                arr[2] = i;
                arr[3] = j;
            }
        }
    }
}
int mod5(int a) { return (a % 5); }
int mod26(int a) { return (a % 26); }
vector<string> readFileToStrings(string path)
{
    vector<string> output;
    string data;
    ifstream indata;   // indata is like cin
    indata.open(path); // opens the file
    if (!indata)
    { // file couldn't be opened
        cerr << "Error: file could not be opened" << endl;
    }

    while (!indata.eof())
    {
        indata >> data; // sets EOF flag if no value found
        // keep reading until end-of-file
        output.push_back(data);
    }
    indata.close();
    return output;
}
void saveTofile(string path, string text)
{
    // Create and open a text file
    ofstream MyFile(path);

    // Write to the file
    if (MyFile.is_open())
    {
        MyFile << text << endl;
    }
    else
    {
        cout << "ERROR writing to file";
    }
    // Close the file
    MyFile.close();
}
void appendTofile(string path, string text)
{
    // Create and open a text file
    ofstream MyFile(path, ios_base::app);

    // Write to the file
    if (MyFile.is_open())
    {
        MyFile << text << endl;
    }
    else
    {
        cout << "ERROR writing to file";
    }
    // Close the file
    MyFile.close();
}