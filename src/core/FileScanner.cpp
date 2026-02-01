#include "FileScanner.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <psapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace SecureCore {

    FileScanner::FileScanner() : monitoring(false), initialized(false) {
    }

    FileScanner::~FileScanner() {
        stopMonitoring();
    }

    bool FileScanner::initialize() {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        if (initialized.load()) {
            return false;
        }

        // Initialize trusted hashes with known good system files
        addTrustedHash("d41d8cd98f00b204e9800998ecf8427e", "MD5"); // Empty file
        
        initialized = true;
        return true;
    }

    bool FileScanner::startMonitoring() {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        if (!initialized.load() || monitoring.load()) {
            return false;
        }

        if (scanDirectory.empty()) {
            return false;
        }

        monitoring = true;
        monitorThread = std::make_unique<std::thread>(&FileScanner::monitorDirectory, this);
        
        return true;
    }

    bool FileScanner::stopMonitoring() {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        if (!monitoring.load()) {
            return false;
        }

        monitoring = false;
        
        if (monitorThread && monitorThread->joinable()) {
            monitorThread->join();
        }
        
        monitorThread.reset();
        return true;
    }

    bool FileScanner::isMonitoring() const {
        return monitoring.load();
    }

    ScanResult FileScanner::validateFile(const std::string& filePath) {
        if (!initialized.load()) {
            return ScanResult::ERROR;
        }

        if (!fileExists(filePath)) {
            return ScanResult::ERROR;
        }

        ScanInfo info = scanFile(filePath);
        return info.result;
    }

    ScanInfo FileScanner::scanFile(const std::string& filePath) {
        ScanInfo info;
        info.filePath = filePath;
        info.result = ScanResult::UNKNOWN;
        info.scanTime = GetTickCount();

        try {
            // Get file information
            WIN32_FILE_ATTRIBUTE_DATA fileData;
            if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileData)) {
                info.fileSize = fileData.nFileSizeLow;
                info.lastModified = fileData.ftLastWriteTime;
            }

            // Calculate file hash
            info.hash = calculateFileHash(filePath);

            // Quick scan first
            info.result = performQuickScan(filePath);
            
            if (info.result == ScanResult::SAFE) {
                // Perform deep scan for executables
                if (isExecutableFile(filePath)) {
                    info.result = performDeepScan(filePath);
                }
            }

            // Add to recent scans
            std::lock_guard<std::mutex> lock(scannerMutex);
            recentScans.push_back(info);
            
            // Keep only last 100 scans
            if (recentScans.size() > 100) {
                recentScans.erase(recentScans.begin());
            }

        } catch (...) {
            info.result = ScanResult::ERROR;
            info.details = "Exception during scan";
        }

        return info;
    }

    bool FileScanner::addTrustedHash(const std::string& hash, const std::string& algorithm) {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        std::string key = algorithm + ":" + hash;
        trustedHashes[key] = true;
        return true;
    }

    bool FileScanner::removeTrustedHash(const std::string& hash) {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        // Remove from all algorithms
        for (auto it = trustedHashes.begin(); it != trustedHashes.end();) {
            if (it->first.find(":" + hash) != std::string::npos) {
                it = trustedHashes.erase(it);
            } else {
                ++it;
            }
        }
        
        return true;
    }

    bool FileScanner::isTrustedHash(const std::string& hash) const {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        // Check all algorithms
        for (const auto& pair : trustedHashes) {
            if (pair.first.find(":" + hash) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }

    std::vector<ScanInfo> FileScanner::getRecentScans() const {
        std::lock_guard<std::mutex> lock(scannerMutex);
        return recentScans;
    }

    void FileScanner::clearScanHistory() {
        std::lock_guard<std::mutex> lock(scannerMutex);
        recentScans.clear();
    }

    bool FileScanner::setScanDirectory(const std::string& directory) {
        std::lock_guard<std::mutex> lock(scannerMutex);
        
        if (monitoring.load()) {
            return false;
        }
        
        if (!fileExists(directory)) {
            return false;
        }
        
        scanDirectory = directory;
        return true;
    }

    std::string FileScanner::getScanDirectory() const {
        std::lock_guard<std::mutex> lock(scannerMutex);
        return scanDirectory;
    }

    FileHash FileScanner::calculateFileHash(const std::string& filePath, const std::string& algorithm) {
        FileHash hash;
        hash.algorithm = algorithm;
        
        if (algorithm == "SHA256") {
            hash.value = calculateSHA256(filePath);
        } else if (algorithm == "MD5") {
            hash.value = calculateMD5(filePath);
        }
        
        return hash;
    }

    bool FileScanner::validateFileSignature(const std::string& filePath) {
        return verifyAuthenticodeSignature(filePath);
    }

    bool FileScanner::detectSuspiciousPatterns(const std::string& filePath) {
        std::string extension = getFileExtension(filePath);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        
        // Check for suspicious extensions
        std::vector<std::string> suspiciousExts = {
            "scr", "pif", "com", "vb", "vbe", "js", "jse", "wsf", "wsh", "msc", "jar"
        };
        
        for (const auto& ext : suspiciousExts) {
            if (ext == extension) {
                return true;
            }
        }
        
        // Check for double extensions
        size_t firstDot = filePath.find_last_of('.');
        size_t secondDot = filePath.find_last_of('.', firstDot - 1);
        if (secondDot != std::string::npos && firstDot != std::string::npos) {
            std::string firstExt = filePath.substr(secondDot + 1, firstDot - secondDot - 1);
            std::string secondExt = filePath.substr(firstDot + 1);
            
            // Common double extension patterns
            if (firstExt == "exe" || firstExt == "scr" || firstExt == "bat") {
                return true;
            }
        }
        
        return false;
    }

    bool FileScanner::isExecutableFile(const std::string& filePath) {
        std::string extension = getFileExtension(filePath);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        
        return extension == "exe" || extension == "dll" || extension == "sys" || 
               extension == "ocx" || extension == "cpl" || extension == "scr";
    }

    bool FileScanner::isScriptFile(const std::string& filePath) {
        std::string extension = getFileExtension(filePath);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        
        return extension == "ps1" || extension == "bat" || extension == "cmd" || 
               extension == "js" || extension == "vbs" || extension == "wsf" ||
               extension == "py" || extension == "pl" || extension == "rb";
    }

    bool FileScanner::isPackedBinary(const std::string& filePath) {
        if (!isExecutableFile(filePath)) {
            return false;
        }
        
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        
        // Read first 1024 bytes
        std::vector<char> buffer(1024);
        file.read(buffer.data(), buffer.size());
        size_t bytesRead = file.gcount();
        file.close();
        
        // Simple packed binary detection
        // Look for common packer signatures
        std::vector<std::string> packerSignatures = {
            "UPX", "PECompact", "ASPack", "FSG", "MEW", "Themida", "WinLicense"
        };
        
        std::string data(buffer.data(), bytesRead);
        for (const auto& signature : packerSignatures) {
            if (data.find(signature) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }

    ScanResult FileScanner::performDeepScan(const std::string& filePath) {
        // Check if file is packed
        if (isPackedBinary(filePath)) {
            return ScanResult::SUSPICIOUS;
        }
        
        // Validate digital signature
        if (!validateFileSignature(filePath)) {
            return ScanResult::SUSPICIOUS;
        }
        
        // Check against trusted hashes
        FileHash hash = calculateFileHash(filePath);
        if (isTrustedHash(hash.value)) {
            return ScanResult::SAFE;
        }
        
        return ScanResult::SUSPICIOUS;
    }

    ScanResult FileScanner::performQuickScan(const std::string& filePath) {
        // Check if file exists
        if (!fileExists(filePath)) {
            return ScanResult::ERROR;
        }
        
        // Check for script files
        if (isScriptFile(filePath)) {
            return ScanResult::MALICIOUS;
        }
        
        // Check for suspicious patterns
        if (detectSuspiciousPatterns(filePath)) {
            return ScanResult::SUSPICIOUS;
        }
        
        // Check file size (basic heuristic)
        DWORD size = getFileSize(filePath);
        if (size == 0 || size > 100 * 1024 * 1024) { // 100MB limit
            return ScanResult::SUSPICIOUS;
        }
        
        return ScanResult::SAFE;
    }

    void FileScanner::monitorDirectory() {
        // This would implement directory monitoring using ReadDirectoryChangesW
        // For now, it's a placeholder
        while (monitoring.load()) {
            Sleep(1000); // Poll every second
        }
    }

    void FileScanner::onFileChanged(const std::string& filePath) {
        // Automatically scan changed files
        scanFile(filePath);
    }

    std::string FileScanner::calculateSHA256(const std::string& filePath) {
        // Simplified SHA256 calculation
        // In production, use proper crypto API
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }
        
        // For now, return a placeholder
        return "sha256_placeholder_hash";
    }

    std::string FileScanner::calculateMD5(const std::string& filePath) {
        // Simplified MD5 calculation
        // In production, use proper crypto API
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }
        
        // For now, return a placeholder
        return "md5_placeholder_hash";
    }

    std::string FileScanner::getFileExtension(const std::string& filePath) const {
        size_t dotPos = filePath.find_last_of('.');
        if (dotPos == std::string::npos || dotPos == filePath.length() - 1) {
            return "";
        }
        
        return filePath.substr(dotPos + 1);
    }

    bool FileScanner::fileExists(const std::string& filePath) const {
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        return (attributes != INVALID_FILE_ATTRIBUTES && 
                !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }

    DWORD FileScanner::getFileSize(const std::string& filePath) const {
        WIN32_FILE_ATTRIBUTE_DATA fileData;
        if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileData)) {
            return fileData.nFileSizeLow;
        }
        return 0;
    }

    bool FileScanner::verifyAuthenticodeSignature(const std::string& filePath) {
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

    bool FileScanner::checkCertificateChain(const std::string& filePath) {
        // Additional certificate validation
        return verifyAuthenticodeSignature(filePath);
    }
}
