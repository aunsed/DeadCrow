#pragma once

#include <string>
#include <vector>
#include <random>
#include <stdexcept>

namespace deadcrow {
namespace utils {

class AES {
public:
    // Konstruktor z kluczem
    explicit AES(const std::string& key);
    
    // Generowanie losowego klucza AES-256
    static std::string generateKey();
    
    // Szyfrowanie danych
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);
    std::string encryptToBase64(const std::string& plaintext);
    
    // Deszyfrowanie danych
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted_data);
    std::string decryptFromBase64(const std::string& encrypted_base64);
    
private:
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;  // Wektor inicjalizacyjny dla CBC
    
    // Generowanie losowego IV
    std::vector<uint8_t> generateIV();
    
    // Konwersja między Base64 a binarną reprezentacją
    static std::string toBase64(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> fromBase64(const std::string& base64);
    
    // Padding danych do wielokrotności bloku AES
    static std::vector<uint8_t> padData(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> unpadData(const std::vector<uint8_t>& data);
};

} // namespace utils
} // namespace deadcrow
