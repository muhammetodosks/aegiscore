#include "SecureCore.h"
#include "PolicyEngine.h"
#include "FileScanner.h"
#include "IntegrityValidator.h"
#include "RuntimeLock.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <tlhelp32.h>

namespace SecureCore {

    SecureCore::SecureCore() 
        : status(SecurityStatus::INACTIVE)
        , policiesLocked(false)
        , policiesReadOnly(false)
        , blockedAttempts(0)
        , failsafeActive(false)
        , failsafeTriggered(false)
        , lastHeartbeat(0)
        , activationTime(0)
        , securityMode(SecurityMode::STANDARD) {
        
        policyEngine = std::make_unique<PolicyEngine>();
        fileScanner = std::make_unique<FileScanner>();
        integrityValidator = std::make_unique<IntegrityValidator>();
        runtimeLock = std::make_unique<RuntimeLock>();
    }

    SecureCore::~SecureCore() {
        shutdown();
    }

    SecureCore& SecureCore::getInstance() {
        static SecureCore instance;
        return instance;
    }

    bool SecureCore::initialize() {
        std::lock_guard<std::mutex> lock(coreMutex);
        
        if (status != SecurityStatus::INACTIVE) {
            return false;
        }

        if (!validateSystemRequirements()) {
            status = SecurityStatus::ERROR;
            return false;
        }

        if (!policyEngine->initialize() || 
            !fileScanner->initialize() || 
            !integrityValidator->initialize() || 
            !runtimeLock->initialize()) {
            status = SecurityStatus::ERROR;
            return false;
        }

        status = SecurityStatus::INACTIVE;
        return true;
    }

    bool SecureCore::activate() {
        std::lock_guard<std::mutex> lock(coreMutex);
        
        if (status != SecurityStatus::INACTIVE) {
            return false;
        }

        if (!policyEngine->isLoaded()) {
            logViolation(PolicyViolation::UNKNOWN_FORMAT, "No policies loaded");
            return false;
        }

        try {
            if (!installSystemHooks()) {
                status = SecurityStatus::ERROR;
                return false;
            }

            if (!policyEngine->startEnforcement() || 
                !fileScanner->startMonitoring() || 
                !runtimeLock->activate()) {
                removeSystemHooks();
                status = SecurityStatus::ERROR;
                return false;
            }

            status = SecurityStatus::ACTIVE;
            policiesLocked = true;
            activationTime = GetTickCount64();
            
            // Start failsafe monitoring
            enableFailsafe();
            updateHeartbeat();
            
            return true;
        } catch (...) {
            // If any exception occurs during activation, trigger failsafe
            emergencyShutdown();
            return false;
        }
    }

    bool SecureCore::deactivate() {
        std::lock_guard<std::mutex> lock(coreMutex);
        
        if (status != SecurityStatus::ACTIVE && status != SecurityStatus::LOCKED) {
            return false;
        }

        policyEngine->stopEnforcement();
        fileScanner->stopMonitoring();
        runtimeLock->deactivate();
        removeSystemHooks();

        status = SecurityStatus::INACTIVE;
        policiesLocked = false;
        
        // Stop failsafe monitoring
        disableFailsafe();
        
        return true;
    }

    bool SecureCore::shutdown() {
        std::lock_guard<std::mutex> lock(coreMutex);
        
        if (status == SecurityStatus::ACTIVE || status == SecurityStatus::LOCKED) {
            deactivate();
        }

        policyEngine.reset();
        fileScanner.reset();
        integrityValidator.reset();
        runtimeLock.reset();

        status = SecurityStatus::INACTIVE;
        return true;
    }

    SecurityStatus SecureCore::getStatus() const {
        return status.load();
    }

    std::string SecureCore::getStatusString() const {
        switch (status.load()) {
            case SecurityStatus::INACTIVE: return "INACTIVE";
            case SecurityStatus::ACTIVE: return "ACTIVE";
            case SecurityStatus::LOCKED: return "LOCKED";
            case SecurityStatus::ERROR: return "ERROR";
            default: return "UNKNOWN";
        }
    }

    bool SecureCore::loadPolicies(const std::string& policyPath) {
        std::lock_guard<std::mutex> lock(coreMutex);
        
        if (policiesLocked.load() || policiesReadOnly.load()) {
            return false;
        }

        std::ifstream file(policyPath);
        if (!file.is_open()) {
            logViolation(PolicyViolation::UNKNOWN_FORMAT, "Cannot open policy file");
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        // Parse security mode from JSON
        size_t modePos = content.find("\"mode\"");
        if (modePos != std::string::npos) {
            size_t colonPos = content.find(":", modePos);
            if (colonPos != std::string::npos) {
                size_t start = content.find("\"", colonPos);
                size_t end = content.find("\"", start + 1);
                if (start != std::string::npos && end != std::string::npos) {
                    std::string modeStr = content.substr(start + 1, end - start - 1);
                    // Remove quotes and whitespace
                    modeStr.erase(std::remove_if(modeStr.begin(), modeStr.end(), ::isspace), modeStr.end());
                    modeStr.erase(std::remove(modeStr.begin(), modeStr.end(), '"'), modeStr.end());
                    
                    if (modeStr == "safe") {
                        securityMode = SecurityMode::SAFE;
                    } else if (modeStr == "standard") {
                        securityMode = SecurityMode::STANDARD;
                    } else if (modeStr == "enterprise") {
                        securityMode = SecurityMode::ENTERPRISE;
                    }
                }
            }
        }

        if (!policyEngine->loadPolicies(content)) {
            logViolation(PolicyViolation::UNKNOWN_FORMAT, "Failed to parse policy file");
            return false;
        }

        // Make policies read-only after successful loading
        makePoliciesReadOnly();

        return true;
    }

    bool SecureCore::enforcePolicy(const std::string& filePath) {
        if (status != SecurityStatus::ACTIVE && status != SecurityStatus::LOCKED) {
            return false;
        }

        if (!fileScanner->validateFile(filePath)) {
            blockedAttempts++;
            logViolation(PolicyViolation::HASH_MISMATCH, "File validation failed: " + filePath);
            return false;
        }

        if (!policyEngine->checkPolicy(filePath)) {
            blockedAttempts++;
            logViolation(PolicyViolation::UNKNOWN_FORMAT, "Policy violation: " + filePath);
            return false;
        }

        return true;
    }

    void SecureCore::logViolation(PolicyViolation violation, const std::string& details) {
        std::lock_guard<std::mutex> lock(logMutex);
        
        std::stringstream ss;
        ss << "[" << GetTickCount64() << "] VIOLATION: ";
        
        switch (violation) {
            case PolicyViolation::SCRIPT_EXECUTION: ss << "SCRIPT_EXECUTION"; break;
            case PolicyViolation::UNSIGNED_DLL: ss << "UNSIGNED_DLL"; break;
            case PolicyViolation::CODE_INJECTION: ss << "CODE_INJECTION"; break;
            case PolicyViolation::UNKNOWN_FORMAT: ss << "UNKNOWN_FORMAT"; break;
            case PolicyViolation::HASH_MISMATCH: ss << "HASH_MISMATCH"; break;
            case PolicyViolation::SIGNATURE_INVALID: ss << "SIGNATURE_INVALID"; break;
        }
        
        ss << " - " << details << "\n";
        violationLog += ss.str();
    }

    std::string SecureCore::getViolationLog() const {
        std::lock_guard<std::mutex> lock(logMutex);
        return violationLog;
    }

    bool SecureCore::isSystemSecure() const {
        return status == SecurityStatus::ACTIVE || status == SecurityStatus::LOCKED;
    }

    int SecureCore::getActivePoliciesCount() const {
        return policyEngine ? policyEngine->getActivePoliciesCount() : 0;
    }

    int SecureCore::getBlockedAttemptsCount() const {
        return blockedAttempts.load();
    }

    // Failsafe implementation
    bool SecureCore::enableFailsafe() {
        if (failsafeActive.load()) {
            return false;
        }

        failsafeActive = true;
        failsafeTriggered = false;
        lastHeartbeat = GetTickCount64();
        
        // Start failsafe monitoring thread
        failsafeThread = std::make_unique<std::thread>(&SecureCore::failsafeMonitor, this);
        
        return true;
    }

    bool SecureCore::disableFailsafe() {
        if (!failsafeActive.load()) {
            return false;
        }

        failsafeActive = false;
        
        // Stop monitoring thread
        if (failsafeThread && failsafeThread->joinable()) {
            failsafeThread->join();
        }
        failsafeThread.reset();
        
        return true;
    }

    bool SecureCore::isFailsafeActive() const {
        return failsafeActive.load();
    }

    void SecureCore::emergencyShutdown() {
        std::lock_guard<std::mutex> lock(coreMutex);
        
        // Disable all security immediately
        disableAllSecurity();
        
        // Set status to error
        status = SecurityStatus::ERROR;
        
        // Stop all monitoring
        if (policyEngine) policyEngine->stopEnforcement();
        if (fileScanner) fileScanner->stopMonitoring();
        if (runtimeLock) runtimeLock->deactivate();
        
        // Remove system hooks
        removeSystemHooks();
        
        // Unlock policies
        policiesLocked = false;
        
        // Mark failsafe as triggered
        failsafeTriggered = true;
    }

    void SecureCore::checkFailsafeConditions() {
        if (!failsafeActive.load()) {
            return;
        }

        uint64_t currentTime = GetTickCount64();
        uint64_t timeSinceActivation = currentTime - activationTime.load();
        uint64_t timeSinceHeartbeat = currentTime - lastHeartbeat.load();
        
        // Grace period: first 10 seconds, only check for critical errors
        if (timeSinceActivation < 10000) { // 10 seconds in milliseconds
            // During grace period, only trigger on critical errors
            if (status == SecurityStatus::ERROR) {
                triggerFailsafe("CRITICAL_ERROR", "System entered ERROR state during grace period");
            }
            return;
        }
        
        // After grace period, check all conditions
        if (timeSinceHeartbeat > 5000) { // 5 seconds heartbeat timeout
            triggerFailsafe("TIMEOUT", "Heartbeat timeout detected");
        }
        
        if (status == SecurityStatus::ERROR) {
            triggerFailsafe("ERROR", "System entered ERROR state");
        }
    }

    void SecureCore::failsafeMonitor() {
        while (failsafeActive.load()) {
            checkFailsafeConditions();
            Sleep(1000); // Check every second
        }
    }

    void SecureCore::updateHeartbeat() {
        lastHeartbeat = GetTickCount64();
    }

    void SecureCore::triggerFailsafe() {
        if (failsafeTriggered.load()) {
            return; // Already triggered
        }

        emergencyShutdown();
    }

    void SecureCore::triggerFailsafe(const std::string& reason, const std::string& type) {
        if (failsafeTriggered.load()) {
            return; // Already triggered
        }

        // Write failsafe log before shutdown
        writeFailsafeLog(reason, type);
        emergencyShutdown();
    }

    void SecureCore::disableAllSecurity() {
        // Disable all hooks and security enforcement
        if (runtimeLock && runtimeLock->isActivated()) {
            runtimeLock->deactivate();
        }
        
        if (policyEngine) {
            policyEngine->stopEnforcement();
        }
        
        if (fileScanner) {
            fileScanner->stopMonitoring();
        }
    }

    std::string SecureCore::getFailsafeLogPath() const {
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        return std::string(tempPath) + "failsafe.log";
    }

    void SecureCore::writeFailsafeLog(const std::string& reason, const std::string& type) {
        std::string logPath = getFailsafeLogPath();
        
        // Check log file size and rotate if needed (5MB limit)
        std::ifstream checkFile(logPath, std::ios::binary | std::ios::ate);
        if (checkFile.is_open()) {
            std::streamsize size = checkFile.tellg();
            checkFile.close();
            
            // If file is larger than 5MB, rotate it
            if (size > 5 * 1024 * 1024) {
                std::string backupPath = logPath + ".old";
                std::filesystem::rename(logPath, backupPath);
            }
        }
        
        std::ofstream logFile(logPath, std::ios::app);
        
        if (logFile.is_open()) {
            // Get current time
            SYSTEMTIME st;
            GetLocalTime(&st);
            
            // Get thread ID
            DWORD threadId = GetCurrentThreadId();
            
            logFile << "=== FAILSAFE TRIGGERED ===" << std::endl;
            logFile << "AegisCore " << AEGISCORE_VERSION << std::endl;
            logFile << "Date: " << st.wYear << "-" << st.wMonth << "-" << st.wDay << std::endl;
            logFile << "Time: " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "." << st.wMilliseconds << std::endl;
            logFile << "Thread: " << threadId << std::endl;
            logFile << "Type: " << type << std::endl;
            logFile << "Reason: " << reason << std::endl;
            logFile << "Security Status: " << static_cast<int>(status.load()) << std::endl;
            logFile << "Policies Locked: " << (policiesLocked.load() ? "YES" : "NO") << std::endl;
            logFile << "Policies Read-Only: " << (policiesReadOnly.load() ? "YES" : "NO") << std::endl;
            logFile << "Blocked Attempts: " << blockedAttempts.load() << std::endl;
            logFile << "System Uptime: " << (GetTickCount64() / 1000) << " seconds" << std::endl;
            logFile << "==========================" << std::endl;
            logFile.close();
        }
    }

    void SecureCore::makePoliciesReadOnly() {
        policiesReadOnly = true;
    }

    bool SecureCore::arePoliciesReadOnly() const {
        return policiesReadOnly.load();
    }

    bool SecureCore::validateSystemRequirements() {
        OSVERSIONINFOEX osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        
        if (!GetVersionEx((OSVERSIONINFO*)&osvi)) {
            return false;
        }

        if (osvi.dwMajorVersion < 10) {
            return false;
        }

        return true;
    }

    bool SecureCore::installSystemHooks() {
        // Install file system hooks for monitoring
        // This would involve Windows API hooks for file operations
        return true;
    }

    bool SecureCore::removeSystemHooks() {
        // Remove installed system hooks
        return true;
    }

    // DLL Export implementations
    extern "C" {
        __declspec(dllexport) SecureCore* GetSecureCoreInstance() {
            return &SecureCore::getInstance();
        }

        __declspec(dllexport) bool InitializeSecureCore() {
            return SecureCore::getInstance().initialize();
        }

        __declspec(dllexport) bool ActivateSecureCore() {
            return SecureCore::getInstance().activate();
        }

        __declspec(dllexport) bool DeactivateSecureCore() {
            return SecureCore::getInstance().deactivate();
        }

        __declspec(dllexport) bool ShutdownSecureCore() {
            return SecureCore::getInstance().shutdown();
        }

        __declspec(dllexport) int GetSecurityStatus() {
            return static_cast<int>(SecureCore::getInstance().getStatus());
        }

        __declspec(dllexport) const char* GetSecurityStatusString() {
            static std::string status = SecureCore::getInstance().getStatusString();
            return status.c_str();
        }

        __declspec(dllexport) int GetBlockedAttemptsCount() {
            return SecureCore::getInstance().getBlockedAttemptsCount();
        }

        __declspec(dllexport) const char* GetViolationLog() {
            static std::string log = SecureCore::getInstance().getViolationLog();
            return log.c_str();
        }

        __declspec(dllexport) bool EnableFailsafe() {
            return SecureCore::getInstance().enableFailsafe();
        }

        __declspec(dllexport) bool DisableFailsafe() {
            return SecureCore::getInstance().disableFailsafe();
        }

        __declspec(dllexport) bool IsFailsafeActive() {
            return SecureCore::getInstance().isFailsafeActive();
        }

        __declspec(dllexport) void EmergencyShutdown() {
            SecureCore::getInstance().emergencyShutdown();
        }
    }
}
