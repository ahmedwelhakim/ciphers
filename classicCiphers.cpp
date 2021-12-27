#include <iostream>
#include <fstream>
#include <string>
#include <vector>
using namespace std;
string CeaserCipherEncrypt(string text, int s)
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
    ofstream MyFile(path,ios_base::app);

    // Write to the file
    if (MyFile.is_open())
    {
        MyFile << text << endl;
    }
    else
    {
        cout<<"ERROR writing to file";
    }
    // Close the file
    MyFile.close();
}
int main()
{

    vector<string> texts = readFileToStrings("caesar_plain.txt");
    for (size_t i = 0; i < texts.size(); i++)
    {
        string cipher = CeaserCipherEncrypt(texts[i], 3);
        saveTofile("ceaser_cipher_3.txt", cipher);
    }

    return 0;
}