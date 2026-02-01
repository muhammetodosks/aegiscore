#include "IntegrityValidator.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <imagehlp.h>

#pragma comment(lib, "imagehlp.lib")

namespace SecureCore {

    IntegrityValidator::IntegrityValidator() : initialized(false), systemIntact(false) {
    }

    IntegrityValidator::~IntegrityValidator() {
    }

    bool IntegrityValidator::initialize() {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        if (initialized.load()) {
            return false;
        }

        systemIntact = true;
        initialized = true;
        return true;
    }

    bool IntegrityValidator::validateSystem() {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        if (!initialized.load()) {
            return false;
        }

        clearResults();
        
        bool allValid = true;
        
        // Validate all components in baseline
        for (const auto& baseline : baselineHashes) {
            const std::string& componentPath = baseline.first;
            const std::string& expectedHash = baseline.second;
            
            if (!validateComponent(componentPath, expectedHash)) {
                allValid = false;
            }
        }
        
        systemIntact = allValid;
        return allValid;
    }

    bool IntegrityValidator::validateComponent(const std::string& componentPath, const std::string& expectedHash) {
        if (!initialized.load()) {
            return false;
        }

        IntegrityCheck check;
        check.component = componentPath;
        check.expectedHash = expectedHash;
        check.checkTime = GetTickCount();
        
        // Calculate actual hash
        check.actualHash = calculateComponentHash(componentPath);
        
        if (check.actualHash.empty()) {
            check.status = IntegrityStatus::UNKNOWN;
            addCheckResult(check);
            return false;
        }
        
        // Compare hashes
        if (check.actualHash == expectedHash) {
            check.status = IntegrityStatus::VALID;
        } else {
            check.status = IntegrityStatus::TAMPERED;
        }
        
        // Additional validation for executables
        if (check.status == IntegrityStatus::VALID) {
            if (!validateExecutableHeaders(componentPath)) {
                check.status = IntegrityStatus::CORRUPTED;
            } else if (!validateDigitalSignature(componentPath)) {
                check.status = IntegrityStatus::INVALID;
            } else if (detectCodeInjection(componentPath)) {
                check.status = IntegrityStatus::TAMPERED;
            }
        }
        
        addCheckResult(check);
        return check.status == IntegrityStatus::VALID;
    }

    IntegrityStatus IntegrityValidator::checkIntegrity(const std::string& filePath) {
        if (!initialized.load()) {
            return IntegrityStatus::UNKNOWN;
        }

        std::string actualHash = calculateComponentHash(filePath);
        if (actualHash.empty()) {
            return IntegrityStatus::UNKNOWN;
        }

        // Check if we have a baseline for this component
        auto it = baselineHashes.find(filePath);
        if (it == baselineHashes.end()) {
            return IntegrityStatus::UNKNOWN;
        }

        if (actualHash != it->second) {
            return IntegrityStatus::TAMPERED;
        }

        if (!validateExecutableHeaders(filePath)) {
            return IntegrityStatus::CORRUPTED;
        }

        if (!validateDigitalSignature(filePath)) {
            return IntegrityStatus::INVALID;
        }

        if (detectCodeInjection(filePath)) {
            return IntegrityStatus::TAMPERED;
        }

        return IntegrityStatus::VALID;
    }

    std::vector<IntegrityCheck> IntegrityValidator::getLastCheckResults() const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        return checkResults;
    }

    bool IntegrityValidator::setBaseline(const std::string& componentPath) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        std::string hash = calculateComponentHash(componentPath);
        if (hash.empty()) {
            return false;
        }
        
        baselineHashes[componentPath] = hash;
        return true;
    }

    bool IntegrityValidator::loadBaseline(const std::string& baselinePath) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        std::ifstream file(baselinePath);
        if (!file.is_open()) {
            return false;
        }

        baselineHashes.clear();
        
        std::string line;
        while (std::getline(file, line)) {
            size_t separator = line.find('=');
            if (separator != std::string::npos) {
                std::string path = line.substr(0, separator);
                std::string hash = line.substr(separator + 1);
                baselineHashes[path] = hash;
            }
        }

        file.close();
        return true;
    }

    bool IntegrityValidator::saveBaseline(const std::string& baselinePath) const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        std::ofstream file(baselinePath);
        if (!file.is_open()) {
            return false;
        }

        for (const auto& baseline : baselineHashes) {
            file << baseline.first << "=" << baseline.second << std::endl;
        }

        file.close();
        return true;
    }

    bool IntegrityValidator::isSystemIntact() const {
        return systemIntact.load();
    }

    int IntegrityValidator::getValidComponentsCount() const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        int count = 0;
        for (const auto& check : checkResults) {
            if (check.status == IntegrityStatus::VALID) {
                count++;
            }
        }
        
        return count;
    }

    int IntegrityValidator::getInvalidComponentsCount() const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        int count = 0;
        for (const auto& check : checkResults) {
            if (check.status != IntegrityStatus::VALID && check.status != IntegrityStatus::UNKNOWN) {
                count++;
            }
        }
        
        return count;
    }

    std::string IntegrityValidator::calculateComponentHash(const std::string& componentPath) {
        std::ifstream file(componentPath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }

        // Simple hash calculation for demonstration
        // In production, use proper cryptographic hash
        std::stringstream ss;
        ss << std::hex;
        
        char buffer[1024];
        while (file.read(buffer, sizeof(buffer))) {
            for (size_t i = 0; i < file.gcount(); ++i) {
                ss << static_cast<int>(buffer[i]);
            }
        }
        
        file.close();
        return ss.str();
    }

    bool IntegrityValidator::validateExecutableHeaders(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Read DOS header
        IMAGE_DOS_HEADER dosHeader;
        file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
        
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            file.close();
            return false; // Not a valid PE file
        }

        // Seek to NT headers
        file.seekg(dosHeader.e_lfanew, std::ios::beg);
        
        IMAGE_NT_HEADERS ntHeaders;
        file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
        
        file.close();
        
        return ntHeaders.Signature == IMAGE_NT_SIGNATURE;
    }

    bool IntegrityValidator::validateDigitalSignature(const std::string& filePath) {
        // Use WinTrust to validate signature
        WINTRUST_FILE_INFO fileInfo = {0};
        WINTRUST_DATA winTrustData = {0};
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = std::wstring(filePath.begin(), filePath.end()).c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;
        
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = NULL;
        winTrustData.pSIPClientData = NULL;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = NULL;
        winTrustData.pwszURLReference = NULL;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;
        
        LONG result = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
        
        // Clean up
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &winTrustData);
        
        return result == ERROR_SUCCESS;
    }

    bool IntegrityValidator::detectCodeInjection(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Read file into memory for analysis
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<char> buffer(fileSize);
        file.read(buffer.data(), fileSize);
        file.close();

        // Simple code injection detection
        // Look for suspicious patterns in executable sections
        std::vector<std::string> suspiciousPatterns = {
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "SetWindowsHookEx",
            "LoadLibrary"
        };

        std::string content(buffer.data(), fileSize);
        for (const auto& pattern : suspiciousPatterns) {
            if (content.find(pattern) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    void IntegrityValidator::clearResults() {
        checkResults.clear();
    }

    void IntegrityValidator::addCheckResult(const IntegrityCheck& check) {
        checkResults.push_back(check);
    }
}
