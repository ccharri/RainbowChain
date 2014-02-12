
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <fstream>
#include <cstring>

#include <openssl/sha.h>   // SHA256

using std::cout; using std::cin; using std::endl; using std::string; using std::ifstream;

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

int main(int argc, char** argv)
{
   string dataFile;
   string passFile;
   char buffer[160/8];
 	
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
   		// cout << line << endl;

   		while(pfile >> password)
   		{
   			SHA1((const unsigned char *)password.c_str(), password.length(), (unsigned char *) buffer);
   			if(strcmp(line.c_str(), buffer) == 0)
			{
				cout << "Password cracked - " << line << " - " << password << endl;
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