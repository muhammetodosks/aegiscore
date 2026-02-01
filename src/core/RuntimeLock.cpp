#include "RuntimeLock.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace SecureCore {

    // Static instance for hook procedures
    static RuntimeLock* g_instance = nullptr;

    RuntimeLock::RuntimeLock() 
        : initialized(false)
        , activated(false)
        , policyLocked(false)
        , fileSystemLocked(false)
        , registryLocked(false)
        , memoryLocked(false)
        , monitoring(false)
        , keyboardHook(nullptr)
        , mouseHook(nullptr)
        , windowHook(nullptr) {
        
        g_instance = this;
    }

    RuntimeLock::~RuntimeLock() {
        deactivate();
    }

    bool RuntimeLock::initialize() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (initialized.load()) {
            return false;
        }

        initialized = true;
        return true;
    }

    bool RuntimeLock::activate() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!initialized.load() || activated.load()) {
            return false;
        }

        // Install system hooks for real enforcement
        if (!installSystemHooks()) {
            return false;
        }

        if (!installFileSystemHooks()) {
            removeSystemHooks();
            return false;
        }

        if (!installRegistryHooks()) {
            removeFileSystemHooks();
            removeSystemHooks();
            return false;
        }

        if (!installMemoryProtection()) {
            removeRegistryHooks();
            removeFileSystemHooks();
            removeSystemHooks();
            return false;
        }

        // Start monitoring thread
        monitoring = true;
        monitorThread = std::make_unique<std::thread>(&RuntimeLock::monitorSystem, this);

        activated = true;
        return true;
    }

    bool RuntimeLock::deactivate() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!activated.load()) {
            return false;
        }

        stopMonitoring();
        removeMemoryProtection();
        removeRegistryHooks();
        removeFileSystemHooks();
        removeSystemHooks();

        activated = false;
        policyLocked = false;
        fileSystemLocked = false;
        registryLocked = false;
        memoryLocked = false;
        return true;
    }

    bool RuntimeLock::isActivated() const {
        return activated.load();
    }

    LockStatus RuntimeLock::getStatus() const {
        if (!initialized.load()) {
            return LockStatus::ERROR;
        }
        
        if (activated.load()) {
            return LockStatus::LOCKED;
        }
        
        return LockStatus::UNLOCKED;
    }

    std::string RuntimeLock::getStatusString() const {
        switch (getStatus()) {
            case LockStatus::UNLOCKED: return "UNLOCKED";
            case LockStatus::LOCKED: return "LOCKED";
            case LockStatus::ERROR: return "ERROR";
            default: return "UNKNOWN";
        }
    }

    bool RuntimeLock::lockPolicyModification() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!activated.load()) {
            return false;
        }

        policyLocked = true;
        return true;
    }

    bool RuntimeLock::unlockPolicyModification() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        policyLocked = false;
        return true;
    }

    bool RuntimeLock::isPolicyLocked() const {
        return policyLocked.load();
    }

    bool RuntimeLock::lockFileSystem() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!activated.load()) {
            return false;
        }

        fileSystemLocked = true;
        return true;
    }

    bool RuntimeLock::unlockFileSystem() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        fileSystemLocked = false;
        return true;
    }

    bool RuntimeLock::isFileSystemLocked() const {
        return fileSystemLocked.load();
    }

    bool RuntimeLock::lockRegistry() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!activated.load()) {
            return false;
        }

        registryLocked = true;
        return true;
    }

    bool RuntimeLock::unlockRegistry() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        registryLocked = false;
        return true;
    }

    bool RuntimeLock::isRegistryLocked() const {
        return registryLocked.load();
    }

    bool RuntimeLock::lockMemory() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!activated.load()) {
            return false;
        }

        if (!protectCriticalMemory()) {
            return false;
        }

        memoryLocked = true;
        return true;
    }

    bool RuntimeLock::unlockMemory() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!unprotectCriticalMemory()) {
            return false;
        }

        memoryLocked = false;
        return true;
    }

    bool RuntimeLock::isMemoryLocked() const {
        return memoryLocked.load();
    }

    bool RuntimeLock::preventCodeInjection() {
        if (!activated.load()) {
            return false;
        }

        // Enable DEP and other protections
        DWORD depFlags = PROCESS_DEP_ENABLE;
        if (!SetProcessDEPPolicy(depFlags)) {
            return false;
        }

        return true;
    }

    bool RuntimeLock::preventDllInjection() {
        if (!activated.load()) {
            return false;
        }

        // Set DLL load directory to restrict DLL loading
        if (!SetDllDirectoryW(L"")) {
            return false;
        }

        return true;
    }

    bool RuntimeLock::preventProcessModification() {
        if (!activated.load()) {
            return false;
        }

        // Set process protection
        HANDLE hProcess = GetCurrentProcess();
        DWORD protection = PROCESS_PROTECTION_LEVEL_SAME;
        
        // This would require Windows 10+ and proper privileges
        // For now, return true as placeholder
        return true;
    }

    bool RuntimeLock::startMonitoring() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        if (!activated.load() || monitoring.load()) {
            return false;
        }

        monitoring = true;
        return true;
    }

    bool RuntimeLock::stopMonitoring() {
        std::lock_guard<std::mutex> lock(lockMutex);
        
        monitoring = false;
        return true;
    }

    void RuntimeLock::monitorSystem() {
        while (monitoring.load()) {
            // Monitor running processes and block unauthorized ones
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32W);
                
                if (Process32FirstW(hSnapshot, &pe32)) {
                    do {
                        std::wstring processName(pe32.szExeFile);
                        
                        // Block unauthorized processes
                        if (isUnauthorizedProcess(processName)) {
                            // Terminate the process
                            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                            if (hProcess) {
                                TerminateProcess(hProcess, 1);
                                CloseHandle(hProcess);
                            }
                        }
                        
                    } while (Process32NextW(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
            
            // Update heartbeat for failsafe system
            if (g_instance && g_instance->isActivated()) {
                // This would be called from SecureCore, but we can add a callback
                // For now, just continue monitoring
            }
            
            Sleep(1000); // Check every second
        }
    }
    
    bool RuntimeLock::isUnauthorizedProcess(const std::wstring& processName) {
        // Convert to lowercase for comparison
        std::wstring lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        
        // Block command interpreters and script engines
        if (lowerName.find(L"cmd") != std::wstring::npos ||
            lowerName.find(L"powershell") != std::wstring::npos ||
            lowerName.find(L"pwsh") != std::wstring::npos ||
            lowerName.find(L"wscript") != std::wstring::npos ||
            lowerName.find(L"cscript") != std::wstring::npos ||
            lowerName.find(L"python") != std::wstring::npos ||
            lowerName.find(L"perl") != std::wstring::npos ||
            lowerName.find(L"ruby") != std::wstring::npos) {
            return true;
        }
        
        // Block system tools
        if (lowerName == L"taskmgr.exe" ||
            lowerName == L"regedit.exe" ||
            lowerName == L"msconfig.exe" ||
            lowerName == L"services.msc" ||
            lowerName == L"gpedit.msc") {
            return true;
        }
        
        return false;
    }

    bool RuntimeLock::isMonitoring() const {
        return monitoring.load();
    }

    bool RuntimeLock::installSystemHooks() {
        // Install keyboard hook
        keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandleW(NULL), 0);
        if (!keyboardHook) {
            return false;
        }

        // Install mouse hook
        mouseHook = SetWindowsHookExW(WH_MOUSE_LL, MouseProc, GetModuleHandleW(NULL), 0);
        if (!mouseHook) {
            UnhookWindowsHookEx(keyboardHook);
            keyboardHook = nullptr;
            return false;
        }

        return true;
    }

    bool RuntimeLock::removeSystemHooks() {
        bool success = true;

        if (keyboardHook) {
            if (!UnhookWindowsHookEx(keyboardHook)) {
                success = false;
            }
            keyboardHook = nullptr;
        }

        if (mouseHook) {
            if (!UnhookWindowsHookEx(mouseHook)) {
                success = false;
            }
            mouseHook = nullptr;
        }

        return success;
    }

    bool RuntimeLock::installFileSystemHooks() {
        // This would involve file system filter drivers
        // For now, return true as placeholder
        return true;
    }

    bool RuntimeLock::removeFileSystemHooks() {
        // Remove file system hooks
        return true;
    }

    bool RuntimeLock::installRegistryHooks() {
        // This would involve registry monitoring
        // For now, return true as placeholder
        return true;
    }

    bool RuntimeLock::removeRegistryHooks() {
        // Remove registry hooks
        return true;
    }

    bool RuntimeLock::installMemoryProtection() {
        if (!protectCriticalMemory()) {
            return false;
        }

        if (!preventCodeInjection()) {
            return false;
        }

        if (!preventDllInjection()) {
            return false;
        }

        return true;
    }

    bool RuntimeLock::removeMemoryProtection() {
        return unprotectCriticalMemory();
    }

    LRESULT CALLBACK RuntimeLock::KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0 && g_instance && g_instance->isActivated()) {
            KBDLLHOOKSTRUCT* kbStruct = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
            
            // Block suspicious key combinations for security
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                DWORD vkCode = kbStruct->vkCode;
                
                // Block Command Prompt/PowerShell launch combinations
                bool ctrlPressed = GetAsyncKeyState(VK_CONTROL) & 0x8000;
                bool shiftPressed = GetAsyncKeyState(VK_SHIFT) & 0x8000;
                bool winPressed = GetAsyncKeyState(VK_LWIN) & 0x8000 || GetAsyncKeyState(VK_RWIN) & 0x8000;
                
                // Block Win+R (Run dialog)
                if (winPressed && vkCode == 'R') {
                    return 1; // Block the key
                }
                
                // Block Ctrl+Shift+Esc (Task Manager)
                if (ctrlPressed && shiftPressed && vkCode == VK_ESCAPE) {
                    return 1; // Block the key
                }
                
                // Block Ctrl+Alt+Del (cannot be blocked but can be logged)
                if (ctrlPressed && vkCode == VK_DELETE && GetAsyncKeyState(VK_MENU) & 0x8000) {
                    // Log attempt to bypass security
                    return CallNextHookEx(NULL, nCode, wParam, lParam);
                }
                
                // Block F keys for system access (F1 help, F3 search, etc.)
                if (vkCode >= VK_F1 && vkCode <= VK_F12) {
                    // Allow some F keys but block system ones
                    if (vkCode == VK_F1 || vkCode == VK_F3 || vkCode == VK_F6 || vkCode == VK_F10) {
                        return 1; // Block system access keys
                    }
                }
            }
        }

        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    LRESULT CALLBACK RuntimeLock::MouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0 && g_instance && g_instance->isActivated()) {
            // Log mouse activity for security monitoring
        }

        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    LRESULT CALLBACK RuntimeLock::WindowProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0 && g_instance && g_instance->isActivated()) {
            // Monitor window creation and destruction
        }

        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    bool RuntimeLock::validateProcessAccess(DWORD processId) {
        if (!activated.load()) {
            return true;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        WCHAR processName[MAX_PATH];
        DWORD nameLen = MAX_PATH;
        bool valid = false;

        if (QueryFullProcessImageNameW(hProcess, 0, processName, &nameLen)) {
            std::wstring name(processName);
            valid = isAuthorizedProcess();
        }

        CloseHandle(hProcess);
        return valid;
    }

    bool RuntimeLock::validateFileAccess(const std::string& filePath) {
        if (!activated.load() || !fileSystemLocked.load()) {
            return true;
        }

        // Check if file access is allowed
        // This would implement file access policies
        return true;
    }

    bool RuntimeLock::validateRegistryAccess(HKEY hKey, const std::string& subKey) {
        if (!activated.load() || !registryLocked.load()) {
            return true;
        }

        // Check if registry access is allowed
        // This would implement registry access policies
        return true;
    }

    bool RuntimeLock::protectCriticalMemory() {
        // Protect critical memory regions
        DWORD oldProtect;
        
        // Get current process handle
        HANDLE hProcess = GetCurrentProcess();
        
        // This would protect critical code sections
        // For now, return true as placeholder
        return true;
    }

    bool RuntimeLock::unprotectCriticalMemory() {
        // Unprotect critical memory regions
        return true;
    }

    std::wstring RuntimeLock::getCurrentProcessName() {
        WCHAR processName[MAX_PATH];
        DWORD nameLen = MAX_PATH;
        
        HANDLE hProcess = GetCurrentProcess();
        if (QueryFullProcessImageNameW(hProcess, 0, processName, &nameLen)) {
            return std::wstring(processName);
        }
        
        return L"";
    }

    bool RuntimeLock::isSystemProcess() {
        std::wstring processName = getCurrentProcessName();
        
        // Check if it's a system process
        if (processName.find(L"\\System32\\") != std::wstring::npos ||
            processName.find(L"\\SysWOW64\\") != std::wstring::npos) {
            return true;
        }
        
        return false;
    }

    bool RuntimeLock::isAuthorizedProcess() {
        // Check if current process is authorized to make changes
        return isSystemProcess();
    }
}
