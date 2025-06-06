#pragma once

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

namespace deadcrow {
namespace injector {

class ReflectiveInjector {
public:
    // Konstruktor
    ReflectiveInjector();
    
    // Wstrzyknięcie DLL do procesu
    bool injectDll(const std::string& process_name, const std::vector<uint8_t>& dll_data);
    bool injectDll(DWORD process_id, const std::vector<uint8_t>& dll_data);
    
    // Wstrzyknięcie DLL z pliku
    bool injectDllFromFile(const std::string& process_name, const std::string& dll_path);
    bool injectDllFromFile(DWORD process_id, const std::string& dll_path);
    
    // Ustawienie callbacka do raportowania statusu
    void setStatusCallback(std::function<void(const std::string&)> callback);
    
    // Znalezienie PID procesu po nazwie
    DWORD findProcessId(const std::string& process_name);
    
    // Listowanie dostępnych procesów
    std::vector<std::pair<DWORD, std::string>> listProcesses();
    
private:
    // Callback do raportowania statusu
    std::function<void(const std::string&)> status_callback_;
    
    // Raportowanie statusu
    void reportStatus(const std::string& status);
    
    // Sprawdzanie, czy nie jesteśmy debugowani
    bool checkForDebugging();
    
    // Wczytanie DLL z pliku
    std::vector<uint8_t> loadDllFromFile(const std::string& dll_path);
    
    // Refleksyjne wstrzyknięcie DLL
    bool reflectiveInject(HANDLE process_handle, const std::vector<uint8_t>& dll_data);
    
    // Znalezienie funkcji ReflectiveLoader w DLL
    DWORD findReflectiveLoaderOffset(const std::vector<uint8_t>& dll_data);
    
    // Alokacja pamięci w zdalnym procesie
    LPVOID allocateMemoryInProcess(HANDLE process_handle, SIZE_T size);
    
    // Zapisanie danych do pamięci zdalnego procesu
    bool writeMemoryToProcess(HANDLE process_handle, LPVOID address, const void* data, SIZE_T size);
    
    // Utworzenie zdalnego wątku
    HANDLE createRemoteThread(HANDLE process_handle, LPVOID start_address, LPVOID parameter);
};

} // namespace injector
} // namespace deadcrow
