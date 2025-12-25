#pragma once

#include "Protocol.hpp"
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstdint>

namespace udpworm {

class FilePacketizer {
public:
    explicit FilePacketizer(const std::filesystem::path& file_path);

    // Reads the next block of 'K' symbols, each of 'symbol_size' bytes.
    // Zero-pads if end of file is reached.
    // Returns an empty vector of vectors when all data has been processed.
    std::vector<std::vector<uint8_t>> get_next_block(size_t K, size_t symbol_size);

    uint32_t get_file_id() const;
    uint64_t get_total_file_size() const;
    const std::string& get_file_name() const;
    uint32_t get_permissions() const;
    int64_t get_last_write_time() const;
    bool is_at_eof(); // No longer const

private:
    std::filesystem::path path_;
    std::string name_;
    std::ifstream stream_;
    uint64_t total_size_;
    uint32_t id_;
    uint32_t permissions_;
    int64_t last_write_time_;

    static uint32_t generate_file_id(const std::string& file_name);
};

} // namespace udpworm
