#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

namespace SecureCore {

    enum class IntegrityStatus {
        VALID,
        INVALID,
        CORRUPTED,
        TAMPERED,
        UNKNOWN
    };

    struct IntegrityCheck {
        std::string component;
        std::string expectedHash;
        std::string actualHash;
        IntegrityStatus status;
        DWORD checkTime;
    };

    class IntegrityValidator {
    public:
        IntegrityValidator();
        ~IntegrityValidator();
        
        bool initialize();
        bool validateSystem();
        bool validateComponent(const std::string& componentPath, const std::string& expectedHash);
        
        IntegrityStatus checkIntegrity(const std::string& filePath);
        std::vector<IntegrityCheck> getLastCheckResults() const;
        
        bool setBaseline(const std::string& componentPath);
        bool loadBaseline(const std::string& baselinePath);
        bool saveBaseline(const std::string& baselinePath) const;
        
        bool isSystemIntact() const;
        int getValidComponentsCount() const;
        int getInvalidComponentsCount() const;
        
    private:
        mutable std::mutex validatorMutex;
        std::atomic<bool> initialized;
        std::atomic<bool> systemIntact;
        
        std::vector<IntegrityCheck> checkResults;
        std::unordered_map<std::string, std::string> baselineHashes;
        
        std::string calculateComponentHash(const std::string& componentPath);
        bool validateExecutableHeaders(const std::string& filePath);
        bool validateDigitalSignature(const std::string& filePath);
        bool detectCodeInjection(const std::string& filePath);
        
        void clearResults();
        void addCheckResult(const IntegrityCheck& check);
    };
}
