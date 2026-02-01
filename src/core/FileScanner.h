#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <thread>

namespace SecureCore {

    enum class ScanResult {
        SAFE,
        MALICIOUS,
        SUSPICIOUS,
        UNKNOWN,
        ERROR
    };

    struct FileHash {
        std::string algorithm;
        std::string value;
    };

    struct ScanInfo {
        std::string filePath;
        DWORD fileSize;
        FILETIME lastModified;
        FileHash hash;
        ScanResult result;
        std::string details;
        DWORD scanTime;
    };

    class FileScanner {
    public:
        FileScanner();
        ~FileScanner();
        
        bool initialize();
        bool startMonitoring();
        bool stopMonitoring();
        bool isMonitoring() const;
        
        ScanResult validateFile(const std::string& filePath);
        ScanInfo scanFile(const std::string& filePath);
        
        bool addTrustedHash(const std::string& hash, const std::string& algorithm = "SHA256");
        bool removeTrustedHash(const std::string& hash);
        bool isTrustedHash(const std::string& hash) const;
        
        std::vector<ScanInfo> getRecentScans() const;
        void clearScanHistory();
        
        bool setScanDirectory(const std::string& directory);
        std::string getScanDirectory() const;
        
    private:
        mutable std::mutex scannerMutex;
        std::atomic<bool> monitoring;
        std::atomic<bool> initialized;
        
        std::string scanDirectory;
        std::vector<ScanInfo> recentScans;
        std::unordered_map<std::string, bool> trustedHashes;
        
        std::unique_ptr<std::thread> monitorThread;
        
        // Internal methods
        FileHash calculateFileHash(const std::string& filePath, const std::string& algorithm = "SHA256");
        bool validateFileSignature(const std::string& filePath);
        bool detectSuspiciousPatterns(const std::string& filePath);
        bool isExecutableFile(const std::string& filePath);
        bool isScriptFile(const std::string& filePath);
        bool isPackedBinary(const std::string& filePath);
        
        ScanResult performDeepScan(const std::string& filePath);
        ScanResult performQuickScan(const std::string& filePath);
        
        void monitorDirectory();
        void onFileChanged(const std::string& filePath);
        
        // Hash calculation methods
        std::string calculateSHA256(const std::string& filePath);
        std::string calculateMD5(const std::string& filePath);
        
        // Utility methods
        std::string getFileExtension(const std::string& filePath) const;
        bool fileExists(const std::string& filePath) const;
        DWORD getFileSize(const std::string& filePath) const;
        
        // Signature validation
        bool verifyAuthenticodeSignature(const std::string& filePath);
        bool checkCertificateChain(const std::string& filePath);
    };
}
