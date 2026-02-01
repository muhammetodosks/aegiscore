#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <atomic>

namespace SecureCore {

    struct SecurityPolicy {
        std::string name;
        std::string description;
        bool enabled;
        std::vector<std::string> blockedExtensions;
        std::vector<std::string> allowedPaths;
        std::vector<std::string> blockedPaths;
        bool requireSignature;
        bool requireHash;
        std::string allowedHashAlgorithm;
    };

    class PolicyEngine {
    public:
        PolicyEngine();
        ~PolicyEngine();
        
        bool initialize();
        bool loadPolicies(const std::string& policyPath);
        bool isLoaded() const;
        
        bool startEnforcement();
        bool stopEnforcement();
        bool isEnforcing() const;
        
        bool checkPolicy(const std::string& filePath);
        bool isExtensionBlocked(const std::string& extension) const;
        bool isPathAllowed(const std::string& path) const;
        bool isPathBlocked(const std::string& path) const;
        
        int getActivePoliciesCount() const;
        std::vector<SecurityPolicy> getActivePolicies() const;
        
        const SecurityPolicy& getDefaultPolicy() const;
        
    private:
        std::vector<SecurityPolicy> policies;
        SecurityPolicy defaultPolicy;
        
        mutable std::mutex policyMutex;
        std::atomic<bool> loaded;
        std::atomic<bool> enforcing;
        
        std::unordered_map<std::string, bool> extensionCache;
        std::unordered_map<std::string, bool> pathCache;
        
        bool parsePolicyFile(const std::string& content);
        void initializeDefaultPolicy();
        void clearCaches();
        
        std::string getFileExtension(const std::string& filePath) const;
        std::string normalizePath(const std::string& path) const;
        bool pathMatchesPattern(const std::string& path, const std::string& pattern) const;
    };
}
