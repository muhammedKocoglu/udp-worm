#pragma once

#include <cstdint>
#include <cstddef>
#include <boost/crc.hpp>

namespace udpworm {

constexpr size_t MAX_FILENAME_SIZE = 256;

// This header will be at the beginning of every UDP packet.
struct PacketHeader {
    uint32_t file_id;
    uint64_t total_file_size;
    uint32_t permissions;
    int64_t last_write_time; // Nanoseconds since epoch
    uint32_t block_id;
    uint16_t symbol_id;
    char file_name[MAX_FILENAME_SIZE];
    uint32_t header_crc;
};

// Payload includes a trailing 4-byte CRC32 checksum.
struct MiniHeader {
    uint32_t file_id;
    uint32_t block_id;
    uint16_t symbol_id;
    uint32_t mini_crc;
};

} // namespace udpworm
