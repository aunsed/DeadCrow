#include "anti_debug.h"

namespace deadcrow {
namespace utils {

bool AntiDebug::isBeingDebugged() {
#ifdef _WIN32
    // Windows-specific debugger detection
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // Sprawdzanie NtGlobalFlag w PEB
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        return true;
    }
    
    // Sprawdzanie BeingDebugged flag w PEB
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) {
        return true;
    }
    
    return false;
#else
    // Linux-specific debugger detection
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return true;
    }
    
    // Detach
    ptrace(PTRACE_DETACH, 0, 1, 0);
    
    // Sprawdzanie /proc/self/status dla TracerPid
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = 0;
                sscanf(line + 10, "%d", &pid);
                if (pid != 0) {
                    fclose(f);
                    return true;
                }
                break;
            }
        }
        fclose(f);
    }
    
    return false;
#endif
}

bool AntiDebug::isInVirtualEnvironment() {
    // Sprawdzanie typowych artefaktów maszyn wirtualnych
    std::vector<std::string> vmProcesses = getVirtualizationProcessNames();
    if (checkForProcesses(vmProcesses)) {
        return true;
    }
    
#ifdef _WIN32
    // Sprawdzanie typowych sterowników maszyn wirtualnych
    HANDLE hDevice = CreateFileA("\\\\.\\VBoxMiniRdrDN", 
                               GENERIC_READ, 
                               FILE_SHARE_READ, 
                               NULL, 
                               OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, 
                               NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    
    hDevice = CreateFileA("\\\\.\\vmci", 
                        GENERIC_READ, 
                        FILE_SHARE_READ, 
                        NULL, 
                        OPEN_EXISTING, 
                        FILE_ATTRIBUTE_NORMAL, 
                        NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
#else
    // Sprawdzanie typowych plików maszyn wirtualnych w Linuksie
    FILE* f = fopen("/sys/class/dmi/id/product_name", "r");
    if (f) {
        char buf[1024];
        if (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "VMware") || 
                strstr(buf, "VirtualBox") || 
                strstr(buf, "QEMU") || 
                strstr(buf, "Virtual Machine")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
#endif

    return false;
}

bool AntiDebug::hasAnalysisToolsRunning() {
    std::vector<std::string> debugProcesses = getDebuggerProcessNames();
    return checkForProcesses(debugProcesses);
}

bool AntiDebug::timingCheck() {
    // Debuggery znacząco wpływają na timing wykonania kodu
    auto start = std::chrono::high_resolution_clock::now();
    
    // Operacja, która powinna być szybka (ale nie zoptymalizowana przez kompilator)
    volatile int counter = 0;
    for (int i = 0; i < 10000; i++) {
        counter += i % 2;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Jeśli wykonanie trwało zbyt długo, prawdopodobnie jest debugger
    return duration > 50; // Wartość progowa do dostosowania
}

bool AntiDebug::performAllChecks() {
    // Wykonaj wszystkie testy i zwróć true, jeśli którykolwiek wykrył debugowanie
    if (isBeingDebugged()) return true;
    if (isInVirtualEnvironment()) return true;
    if (hasAnalysisToolsRunning()) return true;
    if (timingCheck()) return true;
    
    return false;
}

bool AntiDebug::checkForProcesses(const std::vector<std::string>& processes) {
#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }
    
    do {
        for (const auto& process : processes) {
            if (_stricmp(pe32.szExeFile, process.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
#else
    // W Linuksie można sprawdzić procesy przez /proc
    DIR* dir = opendir("/proc");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir))) {
            // Sprawdź, czy nazwa katalogu to liczba (PID)
            if (entry->d_type == DT_DIR) {
                char* endptr;
                long pid = strtol(entry->d_name, &endptr, 10);
                if (*endptr == '\0') {
                    // To jest katalog PID
                    char cmdline_path[256];
                    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%ld/cmdline", pid);
                    
                    FILE* cmdline = fopen(cmdline_path, "r");
                    if (cmdline) {
                        char buffer[1024];
                        if (fgets(buffer, sizeof(buffer), cmdline)) {
                            for (const auto& process : processes) {
                                if (strstr(buffer, process.c_str())) {
                                    fclose(cmdline);
                                    closedir(dir);
                                    return true;
                                }
                            }
                        }
                        fclose(cmdline);
                    }
                }
            }
        }
        closedir(dir);
    }
#endif
    return false;
}

std::vector<std::string> AntiDebug::getDebuggerProcessNames() {
    std::vector<std::string> names;
#ifdef _WIN32
    names = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "idag.exe", "idag64.exe", "idaw.exe", "idaw64.exe",
        "dbg.exe", "windbg.exe", "procmon.exe", "procexp.exe",
        "tcpview.exe", "wireshark.exe", "fiddler.exe", "processhacker.exe"
    };
#else
    names = {
        "gdb", "lldb", "strace", "ltrace", "valgrind",
        "radare2", "r2", "ida", "ghidra", "hopper",
        "wireshark", "tcpdump", "processhacker"
    };
#endif
    return names;
}

std::vector<std::string> AntiDebug::getVirtualizationProcessNames() {
    std::vector<std::string> names;
#ifdef _WIN32
    names = {
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
        "vmwareuser.exe", "vgauthservice.exe", "vmacthlp.exe", "vmusrvc.exe"
    };
#else
    names = {
        "VBoxService", "VBoxClient", "vmtoolsd", "vmware-vmblock-fuse",
        "qemu-ga", "spice-vdagent"
    };
#endif
    return names;
}

} // namespace utils
} // namespace deadcrow
