
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <cstring>
#include <ctype.h>
#include <cstdint>

#include <openssl/sha.h>   // SHA256

const size_t SHA_OUTPUT_LEN = 20;

using std::cout; using std::cin; using std::endl; using std::string; using std::ifstream;

class Exception{};

int parseCommands(int argc, char** argv, string* dataFile, string* passFile)
{
	int c;
	opterr = 0;
 	
 	while ((c = getopt (argc, argv, "d:p:")) != -1)
     switch (c)
       {
       case 'd':
         *dataFile = optarg;
         break;
       case 'p':
       	 *passFile = optarg;
       	 break;
       case '?':
       	 cout << "Invalid arguments" << endl;
         return 1;
       default:
         abort ();
    }

    return 0;
}

int char2int(char input)
{
	if(input >= '0' && input <= '9')
	{
		return input - '0';
	}

	if(input >= 'A' && input <= 'F')
	{
		return input - 'A' + 10;
	}

	if(input >= 'a' && input <= 'f')
	{
		return input - 'a' + 10;
	}

	throw Exception();
}


void hexstr_to_bin(const string & digest, char * buffer)
{
	memset(buffer, 0, SHA_OUTPUT_LEN);
	for (int i = 0; i < digest.size(); i += 2)
	{
		char msn = digest[i];
		char lsn = digest[i+1];

		buffer[i/2] = (char2int(msn) << 4) + char2int(lsn);
	}
}

string binary_to_hexstr(char* binary, int len)
{
	std::stringstream ss;
    ss<<std::hex;
    for(int i(0);i<len;++i)
    {
        ss<<(u_int16_t)((binary[i] & 0xF0) >> 4);
    	ss<<(u_int16_t)(binary[i] & 0x0F);
    }
    return ss.str();
}


int main(int argc, char** argv)
{
   string dataFile;
   string passFile;
   char pbuffer[SHA_OUTPUT_LEN];
   char lbuffer[SHA_OUTPUT_LEN];
 	
 	if(parseCommands(argc, argv, &dataFile, &passFile))
 	{
 		return 1;
 	}
   
    cout << "Opening file " << dataFile << " as database." << endl;
   ifstream dfile(dataFile);

   cout << "Opening file " << passFile << " as password." << endl;
   ifstream pfile(passFile);

   string line;
   string password;
   while(dfile >> line)
   {
   		 hexstr_to_bin(line, lbuffer);

   		while(pfile >> password)
   		{
   			memset(&pbuffer, 0, SHA_OUTPUT_LEN);
   			SHA1((const unsigned char *)password.c_str(), password.length(), (unsigned char *) pbuffer);

   			
   			string hex = binary_to_hexstr(pbuffer, SHA_OUTPUT_LEN);
   			// cout << password << "\t- " << "\"";
   			// for(int i = 0; i < hex.length(); ++i)
   			// {
   			// 	cout << hex[i];
   			// }

   			// cout << "\"" <<  endl;
			

			/*
   			 cout << ">"; 
   			 for(int i = 0; i < sizeof(lbuffer); ++i)
   			 {
   			 	cout << lbuffer[i];
   			 }

   			 cout << "\t- " << password << "\t- ";

   			 for(int i = 0; i < sizeof(pbuffer); ++i)
   			 {
   			 	cout << pbuffer[i];
   			 }

   			cout << endl;
   			*/

   			if(memcmp(lbuffer, pbuffer, SHA_OUTPUT_LEN) == 0)
			{
				cout << "Password cracked\t- " << line << "\t- " << password << endl;
			}
			else if(lbuffer[0] == '\0' && lbuffer[1] == '\0' && ((lbuffer[2] & 0xF0) == '\0'))
			{
				char l = lbuffer[2] & 0x0F;
				char r = pbuffer[2]& 0x0F;
				if(memcmp(&l, &r, 1) == 0)
				{
					if(memcmp(lbuffer + 3, pbuffer + 3, SHA_OUTPUT_LEN -3) == 0)
					{
						cout <<"'0'-prefixed Password cracked\t-" << line << "\t- " << password << endl;
					}
				}
			}
   		}

   		pfile.clear();
		pfile.seekg(0, std::ios::beg);
   }

   cout << "Finished" << endl;

   dfile.close();
   pfile.close();

	return 0;
}