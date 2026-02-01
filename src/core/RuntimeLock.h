#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

namespace SecureCore {

    enum class LockStatus {
        UNLOCKED,
        LOCKED,
        ERROR
    };

    class RuntimeLock {
    public:
        RuntimeLock();
        ~RuntimeLock();
        
        bool initialize();
        bool activate();
        bool deactivate();
        bool isActivated() const;
        
        LockStatus getStatus() const;
        std::string getStatusString() const;
        
        bool lockPolicyModification();
        bool unlockPolicyModification();
        bool isPolicyLocked() const;
        
        bool lockFileSystem();
        bool unlockFileSystem();
        bool isFileSystemLocked() const;
        
        bool lockRegistry();
        bool unlockRegistry();
        bool isRegistryLocked() const;
        
        bool lockMemory();
        bool unlockMemory();
        bool isMemoryLocked() const;
        
        // Security enforcement methods
        bool preventCodeInjection();
        bool preventDllInjection();
        bool preventProcessModification();
        
        // Monitoring methods
        bool startMonitoring();
        bool stopMonitoring();
        bool isMonitoring() const;
        
    private:
        mutable std::mutex lockMutex;
        std::atomic<bool> initialized;
        std::atomic<bool> activated;
        std::atomic<bool> policyLocked;
        std::atomic<bool> fileSystemLocked;
        std::atomic<bool> registryLocked;
        std::atomic<bool> memoryLocked;
        std::atomic<bool> monitoring;
        
        // Hook handles
        HHOOK keyboardHook;
        HHOOK mouseHook;
        HHOOK windowHook;
        
        // Internal methods
        bool installSystemHooks();
        bool removeSystemHooks();
        
        bool installFileSystemHooks();
        bool removeFileSystemHooks();
        
        bool installRegistryHooks();
        bool removeRegistryHooks();
        
        bool installMemoryProtection();
        bool removeMemoryProtection();
        
        // Hook procedures
        static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
        static LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam);
        static LRESULT CALLBACK WindowProc(int nCode, WPARAM wParam, LPARAM lParam);
        
        // Security checks
        bool validateProcessAccess(DWORD processId);
        bool validateFileAccess(const std::string& filePath);
        bool validateRegistryAccess(HKEY hKey, const std::string& subKey);
        
        // Protection methods
        bool protectCriticalMemory();
        bool unprotectCriticalMemory();
        
        // Utility methods
        std::wstring getCurrentProcessName();
        bool isSystemProcess();
        bool isAuthorizedProcess();
        
        // System monitoring
        void monitorSystem();
        bool isUnauthorizedProcess(const std::wstring& processName);
    };
}
