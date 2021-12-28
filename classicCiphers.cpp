#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
using namespace std;

// Helper functions prototypes
vector<string> readFileToStrings(string path);
void saveTofile(string path, string text);
void appendTofile(string path, string text);
void search(char keyT[5][5], char a, char b, int arr[]);
void toLowerCase(string *text);
void prepareMatrixTable(string preparedKey, int *letterFrequencies, char matrix[5][5]);
void search(char keyT[5][5], char a, char b, int arr[]);
int mod5(int a);

// Encryption prototypes
string CeaserCipherEncrypt(const string text, const int s);
string PlayFairCipherEncrypt(const string plainText, const string key);

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
    // remove white spaces
    result.erase(remove_if(result.begin(), result.end(), ::isspace), result.end());
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
    indata >> data;

    while (!indata.eof())
    { // keep reading until end-of-file
        output.push_back(data);
        indata >> data; // sets EOF flag if no value found
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