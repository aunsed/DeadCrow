#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <sys/ptrace.h>
#endif

namespace deadcrow {
namespace utils {

class AntiDebug {
public:
    // Sprawdza, czy proces jest debugowany
    static bool isBeingDebugged();
    
    // Sprawdza, czy proces działa w środowisku wirtualnym/sandbox
    static bool isInVirtualEnvironment();
    
    // Sprawdza, czy uruchomione są narzędzia analizy (np. Process Monitor, Wireshark)
    static bool hasAnalysisToolsRunning();
    
    // Wykonuje test opóźnienia czasowego (debuggery wpływają na timing)
    static bool timingCheck();
    
    // Sprawdza wszystkie metody i zwraca true, jeśli wykryto debugowanie
    static bool performAllChecks();
    
private:
    // Sprawdza, czy określone procesy są uruchomione (narzędzia analizy)
    static bool checkForProcesses(const std::vector<std::string>& processes);
    
    // Lista procesów związanych z debugowaniem i analizą
    static std::vector<std::string> getDebuggerProcessNames();
    
    // Lista procesów związanych z maszynami wirtualnymi
    static std::vector<std::string> getVirtualizationProcessNames();
};

} // namespace utils
} // namespace deadcrow
