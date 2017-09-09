#include "crypto.hpp"
#include <iostream>

using namespace std;
string pwdH = "ab29d7b5c589e18b52261ecba1d3a7e7cbf212c6";
string salt = "Saltet til Ola";

const char Alphabet[52] =
{
        'a', 'b', 'c', 'd', 'e', 'f', 'g',
        'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u',
        'v', 'w', 'x', 'y', 'z', 
        'A', 'B', 'C', 'D', 'E', 'F', 'G',
        'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U',
        'V', 'W', 'X', 'Y', 'Z'
};

// Recursive function, keeps clocking characters
// until length is reached

bool GenerateAndCheck(unsigned int length, std::string s)
{
        bool bool1 = false;
        if(length == 0) // when length has been reached
        {
                if (pwdH == Crypto::hex(Crypto::pbkdf2(s, salt, 2048 , 160 / 8))){
                        cout << "Password: " << s << endl;
                        bool1 = true;
                }
                //cout << s << endl;
                return bool1;
        }

        for(unsigned int i = 0; i < 52; i++) // iterate through alphabet
        {
                // Create new string with next character
                // Exit on match
                std::string appended = s + Alphabet[i];
                if(GenerateAndCheck(length-1, appended)==true){
                        exit(0);
                };
        }
        return bool1;
}

void Crack()
{
        cout << "Starting crack ..." << endl;
        static unsigned int stringlength = 1;
        while(stringlength<6)
        {
                // Keep growing till I get it right
                if (GenerateAndCheck(stringlength, "") == true){
                        break;
                }
                stringlength++;
        }
}



int main() {
  cout << "SHA-1 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::sha1("Test")) << endl << endl;

  cout << "SHA-1 with two iterations" << endl;
  cout << Crypto::hex(Crypto::sha1(Crypto::sha1("Test"))) << endl;

  cout << "The derived key from the PBKDF2 algorithm" << endl;
  cout << Crypto::hex(Crypto::pbkdf2("Pass", "Salt")) << endl;

  cout << "MD5 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::md5("Test")) << endl << endl ;

  cout << "SHA-256 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::sha256("Test")) << endl << endl ;

  cout << "SHA-512 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::sha512("Test")) << endl << endl ;

  cout << "Pas key" << endl;
  cout << Crypto::hex(Crypto::pbkdf2("QwE", salt, 2048 , 160 / 8)) << endl << endl ;

  Crack();
}


/*
 SHA-1 with 1 iteration
 640ab2bae07bedc4c163f679a746f7ab7fb5d1fa
 
 SHA-1 with two iterations
 af31c6cbdecd88726d0a9b3798c71ef41f1624d5
 The derived key from the PBKDF2 algorithm
 965939d54088ff7b0aef5473b7f603af3ddd8eb93d9c7fcf8c76380b367ace2d
 MD5 with 1 iteration
 0cbc6611f5540bd0809a388dc95a615b
 
 SHA-256 with 1 iteration
 532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25
 
 SHA-512 with 1 iteration
 c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31
 
 Pas key
 ab29d7b5c589e18b52261ecba1d3a7e7cbf212c6
 
 Starting crack ...
 Password: QwE
 
 real	2m7.746s
 user	2m7.492s
 sys	0m0.020s
 
 */





