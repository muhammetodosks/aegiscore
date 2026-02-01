#pragma once

#define AEGISCORE_VERSION "1.0.0-stable"

#include <windows.h>
#include <string>
#include <memory>
#include <mutex>
#include <atomic>

namespace SecureCore {

    enum class SecurityStatus {
        INACTIVE,
        ACTIVE,
        LOCKED,
        ERROR
    };

    enum class PolicyViolation {
        SCRIPT_EXECUTION,
        UNSIGNED_DLL,
        CODE_INJECTION,
        UNKNOWN_FORMAT,
        HASH_MISMATCH,
        SIGNATURE_INVALID
    };

    class PolicyEngine;
    class FileScanner;
    class IntegrityValidator;
    class RuntimeLock;

    class SecureCore {
    public:
        static SecureCore& getInstance();
        
        bool initialize();
        bool activate();
        bool deactivate();
        bool shutdown();
        
        SecurityStatus getStatus() const;
        std::string getStatusString() const;
        
        bool loadPolicies(const std::string& policyPath);
        bool enforcePolicy(const std::string& filePath);
        
        void logViolation(PolicyViolation violation, const std::string& details);
        std::string getViolationLog() const;
        
        // API for Winsurf UI
        bool isSystemSecure() const;
        int getActivePoliciesCount() const;
        int getBlockedAttemptsCount() const;
        
        // Failsafe methods
        bool enableFailsafe();
        bool disableFailsafe();
        bool isFailsafeActive() const;
        void emergencyShutdown();
        void checkFailsafeConditions();

    private:
        SecureCore();
        ~SecureCore();
        SecureCore(const SecureCore&) = delete;
        SecureCore& operator=(const SecureCore&) = delete;
        
        std::unique_ptr<PolicyEngine> policyEngine;
        std::unique_ptr<FileScanner> fileScanner;
        std::unique_ptr<IntegrityValidator> integrityValidator;
        std::unique_ptr<RuntimeLock> runtimeLock;
        
        mutable std::mutex coreMutex;
        std::atomic<SecurityStatus> status;
        std::atomic<bool> policiesLocked;
        std::atomic<bool> policiesReadOnly;
        std::atomic<int> blockedAttempts;
        
        // Failsafe system (independent from policy lock)
        std::atomic<bool> failsafeActive;
        std::atomic<bool> failsafeTriggered;
        std::atomic<uint64_t> lastHeartbeat;
        std::atomic<uint64_t> activationTime;
        std::unique_ptr<std::thread> failsafeThread;
        
        // Security mode
        enum class SecurityMode {
            SAFE,       // Only script blocking
            STANDARD,   // Script + process blocking
            ENTERPRISE  // Full hooks + process + lock
        };
        std::atomic<SecurityMode> securityMode;
        
        std::string violationLog;
        mutable std::mutex logMutex;
        
        bool validateSystemRequirements();
        bool installSystemHooks();
        bool removeSystemHooks();
        
        // Failsafe internal methods
        void failsafeMonitor();
        void updateHeartbeat();
        void triggerFailsafe();
        void disableAllSecurity();
        void writeFailsafeLog(const std::string& reason, const std::string& type);
        std::string getFailsafeLogPath() const;
        
        // Policy protection
        void makePoliciesReadOnly();
        bool arePoliciesReadOnly() const;
    };

    // DLL Export for external access
    extern "C" {
        __declspec(dllexport) SecureCore* GetSecureCoreInstance();
        __declspec(dllexport) bool InitializeSecureCore();
        __declspec(dllexport) bool ActivateSecureCore();
        __declspec(dllexport) bool DeactivateSecureCore();
        __declspec(dllexport) bool ShutdownSecureCore();
        __declspec(dllexport) int GetSecurityStatus();
        __declspec(dllexport) const char* GetSecurityStatusString();
        __declspec(dllexport) int GetBlockedAttemptsCount();
        __declspec(dllexport) const char* GetViolationLog();
        
        // Failsafe functions
        __declspec(dllexport) bool EnableFailsafe();
        __declspec(dllexport) bool DisableFailsafe();
        __declspec(dllexport) bool IsFailsafeActive();
        __declspec(dllexport) void EmergencyShutdown();
    }
}
