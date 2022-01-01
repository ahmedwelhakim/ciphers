#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
using namespace std;

#define REPEATING_MODE false
#define AUTO_MODE true

// Helper functions prototypes
vector<string> readFileToStrings(string path);
void saveTofile(string path, string text);
void appendTofile(string path, string text);
void search(char keyT[5][5], char a, char b, int arr[]);
void toLowerCase(string *text);
void toUpperCase(string *text);
void prepareMatrixTable(string preparedKey, int *letterFrequencies, char matrix[5][5]);
void search(char keyT[5][5], char a, char b, int arr[]);
int mod5(int a);
int mod26(int a);
void removeSpaces(string *s);
vector<vector<int>> multiply(vector<vector<int>> m1, vector<vector<int>> m2);

// Encryption prototypes
string CeaserCipherEncrypt(const string text, const int s);
string PlayFairCipherEncrypt(const string plainText, const string key);
string HillCipherEncrypt(const string plain, const vector<vector<int>> key);
string VigenerCipherEncrypt(const string plain, const string key, const bool mode);
string VernamCipherEncrypt(const string plain, const string key);