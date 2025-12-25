#pragma once

#include "IFECStrategy.hpp"
#include "Protocol.hpp"
#include <boost/asio.hpp>
#include <memory>
#include <map>
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <atomic>

namespace udpworm {

namespace asio = boost::asio;
using boost::asio::ip::udp;

class UDPReceiver {
public:
    UDPReceiver(uint16_t port,
                std::unique_ptr<IFECStrategy> fec_strategy,
                std::filesystem::path output_directory,
                std::filesystem::path log_file_path = {});
    ~UDPReceiver();

    // K: number of data symbols per block.
    // timeout: duration to wait for a packet before forcing a decode attempt.
    void listen(size_t K, const std::atomic<bool>& running, std::chrono::milliseconds timeout);

private:
    // A single file transfer session
    struct FileSession {
        uint64_t total_file_size = 0;
        uint32_t permissions = 0;
        int64_t last_write_time = 0;
        std::string file_name;
        std::ofstream file_stream;
        std::chrono::steady_clock::time_point last_packet_time;
        uint32_t highest_block_id_seen = 0;

        // block_id -> {symbol_id -> symbol_data}
        std::map<uint32_t, std::map<uint16_t, std::vector<uint8_t>>> incoming_blocks;
        
        // block_id -> decoded_data_symbols
        std::map<uint32_t, std::vector<std::vector<uint8_t>>> reassembled_blocks;
        
        uint32_t next_block_to_write = 0;
        bool header_info_set = false;
        size_t corrected_blocks = 0;
        size_t failed_blocks = 0;
        size_t erasure_count = 0;
        std::filesystem::path file_path;
    };

    void process_packet(const std::vector<uint8_t>& buffer, size_t bytes_transferred, size_t K);
    void write_blocks_to_file(FileSession& session);
    void force_decode_attempts(FileSession& session, size_t K, size_t total_expected, uint32_t up_to_block_id);

    uint16_t port_;
    std::unique_ptr<IFECStrategy> fec_strategy_;
    std::filesystem::path output_directory_;
    std::unique_ptr<std::ofstream> log_stream_;
    asio::io_context io_context_;
    udp::socket socket_;

    // file_id -> session
    std::map<uint32_t, FileSession> sessions_;
};

} // namespace udpworm
