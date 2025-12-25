#include "FilePacketizer.hpp"
#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>

namespace udpworm {

FilePacketizer::FilePacketizer(const std::filesystem::path& file_path)
    : path_(file_path),
      name_(file_path.filename().string()),
      total_size_(0),
      id_(generate_file_id(name_)),
      permissions_(0),
      last_write_time_(0) {

    if (!std::filesystem::exists(path_)) {
        throw std::runtime_error("File does not exist: " + path_.string());
    }
    if (name_.size() >= MAX_FILENAME_SIZE) {
        throw std::runtime_error("Filename is too long (max " + std::to_string(MAX_FILENAME_SIZE - 1) + " chars): " + name_);
    }

    const auto status = std::filesystem::status(path_);
    permissions_ = static_cast<uint32_t>(status.permissions());
    total_size_ = std::filesystem::file_size(path_);
    
    const auto lwt = std::filesystem::last_write_time(path_);
    last_write_time_ = std::chrono::duration_cast<std::chrono::nanoseconds>(lwt.time_since_epoch()).count();

    stream_.open(path_, std::ios::binary);
    if (!stream_.is_open()) {
        throw std::runtime_error("Failed to open file: " + path_.string());
    }
}

uint32_t FilePacketizer::generate_file_id(const std::string& file_name) {
    const auto now = std::chrono::high_resolution_clock::now();
    const auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    
    const std::string to_hash = file_name + std::to_string(timestamp);
    
    const uint64_t hash64 = std::hash<std::string>{}(to_hash);
    
    // Fold 64-bit hash into 32 bits.
    return static_cast<uint32_t>(hash64) ^ static_cast<uint32_t>(hash64 >> 32);
}

std::vector<std::vector<uint8_t>> FilePacketizer::get_next_block(size_t K, size_t symbol_size) {
    if (is_at_eof()) {
        return {};
    }

    std::vector<std::vector<uint8_t>> block;
    block.reserve(K);

    for (size_t i = 0; i < K; ++i) {
        std::vector<uint8_t> symbol(symbol_size, 0); // Zero-pads
        stream_.read(reinterpret_cast<char*>(symbol.data()), symbol_size);
        // If read is short, the rest of 'symbol' is already zero.
        block.push_back(std::move(symbol));
    }

    return block;
}

uint32_t FilePacketizer::get_file_id() const {
    return id_;
}

uint64_t FilePacketizer::get_total_file_size() const {
    return total_size_;
}

const std::string& FilePacketizer::get_file_name() const {
    return name_;
}

uint32_t FilePacketizer::get_permissions() const {
    return permissions_;
}

int64_t FilePacketizer::get_last_write_time() const {
    return last_write_time_;
}

bool FilePacketizer::is_at_eof() {
    stream_.peek(); // Attempts to read one character and check for EOF.
    return stream_.eof();
}

} // namespace udpworm
