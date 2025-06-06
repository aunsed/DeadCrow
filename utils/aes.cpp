#include "aes.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <cstring>

namespace deadcrow {
namespace utils {

// Konstruktor z kluczem
AES::AES(const std::string& key) {
    // Konwersja klucza do wektora bajtów
    key_.assign(key.begin(), key.end());
    
    // Jeśli klucz jest za krótki, rozszerz go
    if (key_.size() < 32) {
        key_.resize(32, 0);
    }
    // Jeśli klucz jest za długi, przytnij go
    else if (key_.size() > 32) {
        key_.resize(32);
    }
    
    // Generuj IV przy inicjalizacji
    iv_ = generateIV();
}

// Generowanie losowego klucza AES-256
std::string AES::generateKey() {
    std::vector<uint8_t> key(32); // 256 bitów = 32 bajty
    
    // Użyj OpenSSL do generowania bezpiecznych losowych bajtów
    if (RAND_bytes(key.data(), key.size()) != 1) {
        throw std::runtime_error("Nie udało się wygenerować klucza AES");
    }
    
    return std::string(key.begin(), key.end());
}

// Generowanie losowego IV
std::vector<uint8_t> AES::generateIV() {
    std::vector<uint8_t> iv(16); // AES używa 128-bitowego bloku = 16 bajtów
    
    // Użyj OpenSSL do generowania bezpiecznych losowych bajtów
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Nie udało się wygenerować IV");
    }
    
    return iv;
}

// Szyfrowanie danych
std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t>& data) {
    // Dodaj padding do danych
    std::vector<uint8_t> padded_data = padData(data);
    
    // Przygotuj bufor na zaszyfrowane dane (rozmiar danych + IV)
    std::vector<uint8_t> encrypted(padded_data.size() + iv_.size());
    
    // Skopiuj IV na początek zaszyfrowanych danych
    std::copy(iv_.begin(), iv_.end(), encrypted.begin());
    
    // Inicjalizacja kontekstu szyfrowania
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Nie udało się utworzyć kontekstu szyfrowania");
    }
    
    // Inicjalizacja szyfrowania
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Nie udało się zainicjalizować szyfrowania");
    }
    
    // Szyfrowanie danych
    int len = 0;
    int ciphertext_len = 0;
    
    if (EVP_EncryptUpdate(ctx, encrypted.data() + iv_.size(), &len, padded_data.data(), padded_data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Błąd podczas szyfrowania");
    }
    ciphertext_len = len;
    
    // Finalizacja szyfrowania
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + iv_.size() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Błąd podczas finalizacji szyfrowania");
    }
    ciphertext_len += len;
    
    // Zwolnij kontekst
    EVP_CIPHER_CTX_free(ctx);
    
    // Przytnij wektor do rzeczywistego rozmiaru zaszyfrowanych danych + IV
    encrypted.resize(ciphertext_len + iv_.size());
    
    return encrypted;
}

// Deszyfrowanie danych
std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t>& encrypted_data) {
    // Sprawdź, czy dane są wystarczająco duże, aby zawierać IV
    if (encrypted_data.size() <= iv_.size()) {
        throw std::runtime_error("Zaszyfrowane dane są za krótkie");
    }
    
    // Wyodrębnij IV z zaszyfrowanych danych
    std::vector<uint8_t> iv(encrypted_data.begin(), encrypted_data.begin() + iv_.size());
    
    // Przygotuj bufor na odszyfrowane dane
    std::vector<uint8_t> decrypted(encrypted_data.size() - iv_.size());
    
    // Inicjalizacja kontekstu deszyfrowania
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Nie udało się utworzyć kontekstu deszyfrowania");
    }
    
    // Inicjalizacja deszyfrowania
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Nie udało się zainicjalizować deszyfrowania");
    }
    
    // Deszyfrowanie danych
    int len = 0;
    int plaintext_len = 0;
    
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, 
                         encrypted_data.data() + iv_.size(), 
                         encrypted_data.size() - iv_.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Błąd podczas deszyfrowania");
    }
    plaintext_len = len;
    
    // Finalizacja deszyfrowania
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Błąd podczas finalizacji deszyfrowania");
    }
    plaintext_len += len;
    
    // Zwolnij kontekst
    EVP_CIPHER_CTX_free(ctx);
    
    // Przytnij wektor do rzeczywistego rozmiaru odszyfrowanych danych
    decrypted.resize(plaintext_len);
    
    // Usuń padding
    return unpadData(decrypted);
}

// Szyfrowanie tekstu do Base64
std::string AES::encryptToBase64(const std::string& plaintext) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> encrypted = encrypt(data);
    return toBase64(encrypted);
}

// Deszyfrowanie z Base64
std::string AES::decryptFromBase64(const std::string& encrypted_base64) {
    std::vector<uint8_t> encrypted = fromBase64(encrypted_base64);
    std::vector<uint8_t> decrypted = decrypt(encrypted);
    return std::string(decrypted.begin(), decrypted.end());
}

// Konwersja do Base64
std::string AES::toBase64(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    
    return result;
}

// Konwersja z Base64
std::vector<uint8_t> AES::fromBase64(const std::string& base64) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(base64.c_str(), base64.length());
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    
    std::vector<uint8_t> buffer(base64.size());
    int decoded_size = BIO_read(bmem, buffer.data(), buffer.size());
    BIO_free_all(bmem);
    
    if (decoded_size <= 0) {
        throw std::runtime_error("Błąd dekodowania Base64");
    }
    
    buffer.resize(decoded_size);
    return buffer;
}

// Padding danych do wielokrotności bloku AES (16 bajtów)
std::vector<uint8_t> AES::padData(const std::vector<uint8_t>& data) {
    // PKCS#7 padding
    size_t block_size = 16;
    size_t padding_size = block_size - (data.size() % block_size);
    
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), padding_size, static_cast<uint8_t>(padding_size));
    
    return padded;
}

// Usuwanie paddingu
std::vector<uint8_t> AES::unpadData(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return data;
    }
    
    // Pobierz wartość ostatniego bajtu (określa ilość paddingu)
    uint8_t padding_value = data.back();
    
    // Sprawdź, czy padding jest poprawny
    if (padding_value > data.size()) {
        throw std::runtime_error("Nieprawidłowy padding");
    }
    
    // Sprawdź, czy wszystkie bajty paddingu mają tę samą wartość
    for (size_t i = data.size() - padding_value; i < data.size(); ++i) {
        if (data[i] != padding_value) {
            throw std::runtime_error("Nieprawidłowy padding");
        }
    }
    
    // Zwróć dane bez paddingu
    return std::vector<uint8_t>(data.begin(), data.end() - padding_value);
}

} // namespace utils
} // namespace deadcrow
