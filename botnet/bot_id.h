#pragma once

#include <string>
#include <vector>
#include <functional>

namespace deadcrow {
namespace botnet {

class BotId {
public:
    // Konstruktor
    BotId();
    
    // Generowanie unikalnego ID bota
    std::string generateBotId();
    
    // Pobieranie informacji o systemie
    std::string getSystemInfo();
    
    // Pobieranie fingerprinta sprzętu
    std::string getHardwareFingerprint();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Zapisanie fingerprinta do JSON
    std::string toJson() const;
    
private:
    // Unikalny identyfikator bota
    std::string bot_id_;
    
    // Informacje o systemie
    std::string system_info_;
    
    // Fingerprint sprzętu
    std::string hardware_fingerprint_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Pobieranie MAC adresu
    std::string getMacAddress();
    
    // Pobieranie informacji o CPU
    std::string getCpuInfo();
    
    // Pobieranie informacji o dysku
    std::string getDiskInfo();
    
    // Pobieranie UUID systemu
    std::string getSystemUuid();
    
    // Generowanie hasha z danych
    std::string generateHash(const std::string& data);
};

} // namespace botnet
} // namespace deadcrow
