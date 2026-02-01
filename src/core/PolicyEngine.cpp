#include "PolicyEngine.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

namespace SecureCore {

    PolicyEngine::PolicyEngine() : loaded(false), enforcing(false) {
        initializeDefaultPolicy();
    }

    PolicyEngine::~PolicyEngine() {
        stopEnforcement();
    }

    bool PolicyEngine::initialize() {
        std::lock_guard<std::mutex> lock(policyMutex);
        
        if (loaded.load()) {
            return false;
        }

        loaded = true;
        return true;
    }

    bool PolicyEngine::loadPolicies(const std::string& policyPath) {
        std::lock_guard<std::mutex> lock(policyMutex);
        
        if (enforcing.load()) {
            return false;
        }

        std::ifstream file(policyPath);
        if (!file.is_open()) {
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        if (!parsePolicyFile(content)) {
            return false;
        }

        clearCaches();
        loaded = true;
        return true;
    }

    bool PolicyEngine::isLoaded() const {
        return loaded.load();
    }

    bool PolicyEngine::startEnforcement() {
        std::lock_guard<std::mutex> lock(policyMutex);
        
        if (!loaded.load() || enforcing.load()) {
            return false;
        }

        enforcing = true;
        return true;
    }

    bool PolicyEngine::stopEnforcement() {
        std::lock_guard<std::mutex> lock(policyMutex);
        
        if (!enforcing.load()) {
            return false;
        }

        enforcing = false;
        return true;
    }

    bool PolicyEngine::isEnforcing() const {
        return enforcing.load();
    }

    bool PolicyEngine::checkPolicy(const std::string& filePath) {
        if (!enforcing.load()) {
            return true;
        }

        std::string normalizedPath = normalizePath(filePath);
        std::string extension = getFileExtension(filePath);
        
        // Convert extension to lowercase for comparison
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        // Check blocked extensions
        if (isExtensionBlocked(extension)) {
            return false;
        }

        // Check blocked paths
        if (isPathBlocked(normalizedPath)) {
            return false;
        }

        // Check allowed paths (if specified)
        if (!defaultPolicy.allowedPaths.empty() && !isPathAllowed(normalizedPath)) {
            return false;
        }

        return true;
    }

    bool PolicyEngine::isExtensionBlocked(const std::string& extension) const {
        if (!enforcing.load()) {
            return false;
        }

        // Check cache first
        auto it = extensionCache.find(extension);
        if (it != extensionCache.end()) {
            return it->second;
        }

        // Check default policy
        for (const auto& blockedExt : defaultPolicy.blockedExtensions) {
            if (blockedExt == extension) {
                extensionCache[extension] = true;
                return true;
            }
        }

        // Check additional policies
        std::lock_guard<std::mutex> lock(policyMutex);
        for (const auto& policy : policies) {
            if (!policy.enabled) continue;
            
            for (const auto& blockedExt : policy.blockedExtensions) {
                if (blockedExt == extension) {
                    extensionCache[extension] = true;
                    return true;
                }
            }
        }

        extensionCache[extension] = false;
        return false;
    }

    bool PolicyEngine::isPathAllowed(const std::string& path) const {
        if (!enforcing.load()) {
            return true;
        }

        // Check cache first
        auto it = pathCache.find("allow_" + path);
        if (it != pathCache.end()) {
            return it->second;
        }

        // Check default policy
        for (const auto& allowedPath : defaultPolicy.allowedPaths) {
            if (pathMatchesPattern(path, allowedPath)) {
                pathCache["allow_" + path] = true;
                return true;
            }
        }

        // Check additional policies
        std::lock_guard<std::mutex> lock(policyMutex);
        for (const auto& policy : policies) {
            if (!policy.enabled) continue;
            
            for (const auto& allowedPath : policy.allowedPaths) {
                if (pathMatchesPattern(path, allowedPath)) {
                    pathCache["allow_" + path] = true;
                    return true;
                }
            }
        }

        pathCache["allow_" + path] = false;
        return false;
    }

    bool PolicyEngine::isPathBlocked(const std::string& path) const {
        if (!enforcing.load()) {
            return false;
        }

        // Check cache first
        auto it = pathCache.find("block_" + path);
        if (it != pathCache.end()) {
            return it->second;
        }

        // Check default policy
        for (const auto& blockedPath : defaultPolicy.blockedPaths) {
            if (pathMatchesPattern(path, blockedPath)) {
                pathCache["block_" + path] = true;
                return true;
            }
        }

        // Check additional policies
        std::lock_guard<std::mutex> lock(policyMutex);
        for (const auto& policy : policies) {
            if (!policy.enabled) continue;
            
            for (const auto& blockedPath : policy.blockedPaths) {
                if (pathMatchesPattern(path, blockedPath)) {
                    pathCache["block_" + path] = true;
                    return true;
                }
            }
        }

        pathCache["block_" + path] = false;
        return false;
    }

    int PolicyEngine::getActivePoliciesCount() const {
        std::lock_guard<std::mutex> lock(policyMutex);
        
        int count = 0;
        for (const auto& policy : policies) {
            if (policy.enabled) count++;
        }
        
        return count + (defaultPolicy.enabled ? 1 : 0);
    }

    std::vector<SecurityPolicy> PolicyEngine::getActivePolicies() const {
        std::lock_guard<std::mutex> lock(policyMutex);
        
        std::vector<SecurityPolicy> activePolicies;
        
        if (defaultPolicy.enabled) {
            activePolicies.push_back(defaultPolicy);
        }
        
        for (const auto& policy : policies) {
            if (policy.enabled) {
                activePolicies.push_back(policy);
            }
        }
        
        return activePolicies;
    }

    const SecurityPolicy& PolicyEngine::getDefaultPolicy() const {
        return defaultPolicy;
    }

    bool PolicyEngine::parsePolicyFile(const std::string& content) {
        // Simple JSON-like parser for policy files
        // In a production environment, use a proper JSON library
        
        try {
            // Clear existing policies
            policies.clear();
            
            // For now, create a basic policy structure
            // This would be replaced with proper JSON parsing
            SecurityPolicy policy;
            policy.name = "Default Security Policy";
            policy.description = "Blocks script execution and unsigned binaries";
            policy.enabled = true;
            policy.requireSignature = true;
            policy.requireHash = true;
            policy.allowedHashAlgorithm = "SHA256";
            
            // Block dangerous extensions
            policy.blockedExtensions = {
                "ps1", "bat", "cmd", "js", "vbs", "wsf", "jar", "py", "pl", "rb"
            };
            
            // Block temporary and system directories
            policy.blockedPaths = {
                "C:\\Windows\\Temp\\*",
                "C:\\Temp\\*",
                "%TEMP%\\*",
                "%TMP%\\*"
            };
            
            policies.push_back(policy);
            
            return true;
        } catch (...) {
            return false;
        }
    }

    void PolicyEngine::initializeDefaultPolicy() {
        defaultPolicy.name = "System Default Policy";
        defaultPolicy.description = "Core security restrictions for Winsurf AI";
        defaultPolicy.enabled = true;
        defaultPolicy.requireSignature = true;
        defaultPolicy.requireHash = true;
        defaultPolicy.allowedHashAlgorithm = "SHA256";
        
        // Block script files
        defaultPolicy.blockedExtensions = {
            "ps1", "bat", "cmd", "js", "vbs", "wsf", "jar", "py", "pl", "rb", "sh"
        };
        
        // Block suspicious paths
        defaultPolicy.blockedPaths = {
            "C:\\Windows\\Temp\\*",
            "C:\\Temp\\*",
            "%TEMP%\\*",
            "%TMP%\\*",
            "C:\\Users\\*\\AppData\\Local\\Temp\\*"
        };
    }

    void PolicyEngine::clearCaches() {
        extensionCache.clear();
        pathCache.clear();
    }

    std::string PolicyEngine::getFileExtension(const std::string& filePath) const {
        size_t dotPos = filePath.find_last_of('.');
        if (dotPos == std::string::npos || dotPos == filePath.length() - 1) {
            return "";
        }
        
        std::string ext = filePath.substr(dotPos + 1);
        // Remove query parameters if any
        size_t queryPos = ext.find('?');
        if (queryPos != std::string::npos) {
            ext = ext.substr(0, queryPos);
        }
        
        return ext;
    }

    std::string PolicyEngine::normalizePath(const std::string& path) const {
        std::string normalized = path;
        
        // Convert forward slashes to backslashes
        std::replace(normalized.begin(), normalized.end(), '/', '\\');
        
        // Convert to lowercase for case-insensitive comparison
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
        
        // Expand environment variables (basic implementation)
        if (normalized.find("%temp%") == 0 || normalized.find("%tmp%") == 0) {
            char tempPath[MAX_PATH];
            if (GetTempPathA(MAX_PATH, tempPath)) {
                normalized = std::string(tempPath) + normalized.substr(5);
            }
        }
        
        return normalized;
    }

    bool PolicyEngine::pathMatchesPattern(const std::string& path, const std::string& pattern) const {
        // Simple wildcard matching
        // In production, use proper pattern matching
        
        if (pattern.back() == '*') {
            std::string prefix = pattern.substr(0, pattern.length() - 1);
            return path.find(prefix) == 0;
        }
        
        return path == pattern;
    }
}
