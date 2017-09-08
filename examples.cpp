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

bool Generate(unsigned int length, std::string s)
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
		// Call generate again until string has reached it's length
		std::string appended = s + Alphabet[i];
		if(Generate(length-1, appended)==true){
			exit(0);
		};
	}
	return bool1;
}

void Crack()
{
	static unsigned int stringlength = 1;
	while(stringlength<6)
	{
		// Keep growing till I get it right
		if (Generate(stringlength, "") == true){
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
    
  
  cout << "Starting crack ..." << endl; 
  Crack();
}



