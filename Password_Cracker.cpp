// John Norwood
// Chris Harris
// EECS 588
// Password_Cracker.cpp


#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <ctype.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <time.h>

#include <openssl/sha.h>   // SHA256

using std::cout; using std::cin; using std::endl; using std::string; using std::ifstream; using std::vector;
using std::atomic; using std::time_t; using std::time; using std::thread; using std::mutex;


const size_t SHA_OUTPUT_LEN = 20;
const size_t THREAD_MAX = 8;

atomic<int> g_num_cracked (0);
mutex g_file_mutex;

int g_num_database_entries = 0;
time_t g_startTime;
time_t g_endTime;

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

void loadPasswords(ifstream &pfile, vector<string> &passwords)
{
	string password;
	while(pfile >> password)
	{
		passwords.push_back(password);
	}

	cout << "Loaded " << passwords.size() << " passwords." << endl;
}

void comparePassword(ifstream& ifile, const vector<string>& passwords)
{
	g_file_mutex.lock();

	string line;
	if(!(ifile >> line)){
		g_file_mutex.unlock();
		return;
	}

	g_file_mutex.unlock();

	g_num_database_entries++;

	char lbuffer[SHA_OUTPUT_LEN];
	char pbuffer[SHA_OUTPUT_LEN];

	memset(&lbuffer, 0, SHA_OUTPUT_LEN);
	hexstr_to_bin(line, lbuffer);

	for(auto it = passwords.begin(); it != passwords.end(); it++)
	{
		memset(&pbuffer, 0, SHA_OUTPUT_LEN);
		SHA1((const unsigned char *)it->c_str(), it->length(), (unsigned char *) pbuffer);

		if(memcmp(lbuffer, pbuffer, SHA_OUTPUT_LEN) == 0)
		{
			cout << "Password cracked\t- " << line << "\t- " << *it << endl;
			g_num_cracked++;
		}
		else if(lbuffer[0] == '\0' && lbuffer[1] == '\0' && ((lbuffer[2] & 0xF0) == '\0'))
		{
			char l = lbuffer[2] & 0x0F;
			char r = pbuffer[2]& 0x0F;
			if(memcmp(&l, &r, 1) == 0)
			{
				if(memcmp(lbuffer + 3, pbuffer + 3, SHA_OUTPUT_LEN -3) == 0)
				{
					cout <<"'0'-prefixed Password cracked\t-" << line << "\t- " << *it << endl;
					g_num_cracked++;
				}
			}
		}
	}
}

void fileThread(ifstream& dfile, const vector<string>& passwords)
{
	g_file_mutex.lock();
	while(dfile.good())
	{
		g_file_mutex.unlock();
		comparePassword(dfile, passwords);
		g_file_mutex.lock();
	}
	g_file_mutex.unlock();
}

int main(int argc, char** argv)
{
   string dataFile;
   string passFile;
   vector<string> passwords;
   char lbuffer[SHA_OUTPUT_LEN];
   vector<thread> threads;
 	
 	if(parseCommands(argc, argv, &dataFile, &passFile))
 	{
 		return 1;
 	}
   
    cout << "Opening file " << dataFile << " as database." << endl;
   ifstream dfile(dataFile);

   cout << "Opening file " << passFile << " as password." << endl;
   ifstream pfile(passFile);

   loadPasswords(pfile, passwords);

   time(&g_startTime);

   for(int i = 0; i < THREAD_MAX; ++i)
   {
   		threads.emplace_back(fileThread, std::ref(dfile), passwords);
   }

   for(auto& thread : threads)
   {
   		thread.join();
   }

   // string line;
   // string password;
   // while(dfile >> line)
   // {
   // 		// comparePassword(line, passwords);
   // 		threads[(g_num_database_entries++) % THREAD_MAX] = thread(comparePassword, line, passwords);

   // 		// if(g_thread_count > THREAD_MAX)
   // 		// {
   // 			threads[(g_num_database_entries) % THREAD_MAX].detach();
   // 		// }
   // }

   time(&g_endTime);

   cout << "Finished" << endl;

   cout << g_num_cracked << " passwords cracked out of " << g_num_database_entries << " total entries." << endl;
   cout << ((float)g_num_cracked)/((float)g_num_database_entries) << "% cracked" << endl;
   cout << g_endTime - g_startTime << " seconds total." << endl;

   dfile.close();
   pfile.close();

	return 0;
}
