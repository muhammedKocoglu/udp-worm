#include "UDPReceiver.hpp"
#include "RaptorQFEC.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <limits>
#include <cstddef>
#include <cstring>
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <openssl/evp.h>

namespace udpworm {

namespace {
std::string calculate_md5(const std::string& path) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return {};
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return {};
    }

    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    std::vector<char> buffer(128 * 1024);
    while (file) {
        file.read(buffer.data(), buffer.size());
        const std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<size_t>(bytes_read)) != 1) {
                EVP_MD_CTX_free(ctx);
                return {};
            }
        }
    }
    if (file.bad()) {
        std::cerr << "[Error] Failed to read file for MD5 calculation at path: " << path << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < md_len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(md_value[i]);
    }
    return oss.str();
}

size_t count_missing_data_symbols(const std::map<uint16_t, std::vector<uint8_t>>& symbols, size_t K) {
    size_t missing = 0;
    for (size_t i = 0; i < K; ++i) {
        if (symbols.find(static_cast<uint16_t>(i)) == symbols.end()) {
            ++missing;
        }
    }
    return missing;
}
} // namespace

UDPReceiver::UDPReceiver(uint16_t port,
                         std::unique_ptr<IFECStrategy> fec_strategy,
                         std::filesystem::path output_directory,
                         std::filesystem::path log_file_path)
    : port_(port),
      fec_strategy_(std::move(fec_strategy)),
      output_directory_(output_directory.empty() ? "." : std::move(output_directory)),
      io_context_(),
      socket_(io_context_, udp::endpoint(udp::v4(), port)) {
    try {
        std::filesystem::create_directories(output_directory_);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Warning: Failed to create output directory " << output_directory_
                  << ": " << e.what() << std::endl;
    }

    if (!log_file_path.empty()) {
        log_stream_ = std::make_unique<std::ofstream>(log_file_path, std::ios::app);
        if (!log_stream_->is_open()) {
            std::cerr << "Warning: Failed to open log file " << log_file_path << std::endl;
            log_stream_.reset();
        }
    }

    boost::system::error_code ec;
    socket_.set_option(asio::socket_base::receive_buffer_size(8 * 1024 * 1024), ec);
    if (ec) {
        std::cerr << "Warning: Failed to set receive buffer size: " << ec.message() << std::endl;
    }
    socket_.set_option(asio::socket_base::send_buffer_size(8 * 1024 * 1024), ec);
    if (ec) {
        std::cerr << "Warning: Failed to set send buffer size: " << ec.message() << std::endl;
    }
}

UDPReceiver::~UDPReceiver() {
    for (auto& pair : sessions_) {
        FileSession& session = pair.second;
        if (session.file_stream.is_open()) {
            session.file_stream.close();
            try {
                const std::filesystem::path path =
                    session.file_path.empty() ? std::filesystem::path(session.file_name) : session.file_path;
                // Truncate the file to its correct size, removing padding.
                std::filesystem::resize_file(path, session.total_file_size);
            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "Error truncating file " << session.file_name << ": " << e.what() << std::endl;
            }
        }
    }
}

void UDPReceiver::listen(size_t K, const std::atomic<bool>& running, std::chrono::milliseconds timeout) {
    socket_.non_blocking(true);
    const size_t M = (K == 50) ? 10 : (K == 100) ? 20 : 4;
    const size_t total_expected = K + M;

    while (running) {
        try {
            std::vector<uint8_t> recv_buffer(65535); // Max UDP packet size
            udp::endpoint sender_endpoint;
            boost::system::error_code error;

            size_t bytes_transferred = socket_.receive_from(asio::buffer(recv_buffer), sender_endpoint, 0, error);

            if (error == asio::error::would_block || error == asio::error::try_again) {
                // No data available. Check for timeouts on active sessions.
                for (auto& pair : sessions_) {
                    FileSession& session = pair.second;
                    if (session.header_info_set && 
                        std::chrono::steady_clock::now() - session.last_packet_time > timeout) {
                        
                        force_decode_attempts(session, K, total_expected, std::numeric_limits<uint32_t>::max());
                        // To prevent repeated timeout triggers, update the time
                        session.last_packet_time = std::chrono::steady_clock::now();
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            if (error) {
                throw boost::system::system_error(error);
            }

            process_packet(recv_buffer, bytes_transferred, K);

        } catch (const boost::system::system_error& e) {
            if (running) {
                std::cerr << "Socket receive error: " << e.what() << std::endl;
            }
        }
    }
}

void UDPReceiver::process_packet(const std::vector<uint8_t>& buffer, size_t bytes_transferred, size_t K) {
    const size_t header_bytes = sizeof(PacketHeader) + (2 * sizeof(MiniHeader));
    if (bytes_transferred < (header_bytes + sizeof(uint32_t))) {
        return; 
    }
    const size_t M = (K == 50) ? 10 : (K == 100) ? 20 : 4;
    const size_t total_expected = K + M;

    const PacketHeader* full_header = reinterpret_cast<const PacketHeader*>(buffer.data());
    boost::crc_32_type full_crc;
    full_crc.process_bytes(full_header, offsetof(PacketHeader, header_crc));
    const bool full_header_valid = (full_crc.checksum() == full_header->header_crc);

    uint32_t file_id = 0;
    uint32_t block_id = 0;
    uint16_t symbol_id = 0;

    bool used_mini_header = false;
    bool used_mini_backup = false;

    if (full_header_valid) {
        file_id = full_header->file_id;
        block_id = full_header->block_id;
        symbol_id = full_header->symbol_id;
    } else {
        const auto* mini_header = reinterpret_cast<const MiniHeader*>(buffer.data() + sizeof(PacketHeader));
        const auto* mini_header_backup =
            reinterpret_cast<const MiniHeader*>(buffer.data() + sizeof(PacketHeader) + sizeof(MiniHeader));

        boost::crc_32_type mini_crc;
        mini_crc.process_bytes(mini_header, offsetof(MiniHeader, mini_crc));
        const bool mini_valid = (mini_crc.checksum() == mini_header->mini_crc);

        if (mini_valid) {
            file_id = mini_header->file_id;
            block_id = mini_header->block_id;
            symbol_id = mini_header->symbol_id;
            used_mini_header = true;
        } else {
            boost::crc_32_type mini_backup_crc;
            mini_backup_crc.process_bytes(mini_header_backup, offsetof(MiniHeader, mini_crc));
            const bool mini_backup_valid = (mini_backup_crc.checksum() == mini_header_backup->mini_crc);

            if (mini_backup_valid) {
                file_id = mini_header_backup->file_id;
                block_id = mini_header_backup->block_id;
                symbol_id = mini_header_backup->symbol_id;
                used_mini_backup = true;
            } else {
                std::cerr << "[Security] Header CRC failed for all headers. Dropping packet." << std::endl;
                return;
            }
        }
    }

    if (used_mini_header) {
        std::cerr << "[Warning] Block " << block_id << " Symbol " << symbol_id
                  << ": Using MiniHeader fallback." << std::endl;
    } else if (used_mini_backup) {
        std::cerr << "[Warning] Block " << block_id << " Symbol " << symbol_id
                  << ": Using MiniHeader fallback." << std::endl;
    }

    FileSession& session = sessions_[file_id];
    session.last_packet_time = std::chrono::steady_clock::now();

    if (!session.file_stream.is_open() && session.header_info_set) {
        return; // File already finalized
    }

    if (full_header_valid && !session.header_info_set) {
        session.file_name = std::string(full_header->file_name);
        session.total_file_size = full_header->total_file_size;
        session.permissions = full_header->permissions;
        session.last_write_time = full_header->last_write_time;
        session.file_path = output_directory_ / session.file_name;
        session.file_stream.open(session.file_path, std::ios::binary | std::ios::trunc);
        if (!session.file_stream.is_open()) {
            sessions_.erase(full_header->file_id);
            return;
        }
        session.header_info_set = true;
        std::cout << "[RECEPTION] Started: " << session.file_name << std::endl;
        write_blocks_to_file(session);
    }

    if (block_id < session.next_block_to_write) {
        return; // Old packet, already written
    }

    // If we receive a packet from a much newer block, force decode older ones.
    if (block_id > session.highest_block_id_seen) {
        if (session.highest_block_id_seen > 0) { // Avoid triggering on the very first packet
             force_decode_attempts(session, K, total_expected, block_id);
        }
        session.highest_block_id_seen = block_id;
    }

    const size_t payload_length = bytes_transferred - header_bytes - sizeof(uint32_t);
    const uint8_t* payload_start = buffer.data() + header_bytes;
    uint32_t received_payload_crc = 0;
    std::memcpy(&received_payload_crc, buffer.data() + header_bytes + payload_length, sizeof(received_payload_crc));
    boost::crc_32_type payload_crc;
    payload_crc.process_bytes(payload_start, payload_length);
    if (payload_crc.checksum() != received_payload_crc) {
        std::cerr << "[Data Integrity] Block " << block_id << " Symbol " << symbol_id
                  << ": Payload CRC mismatch." << std::endl;
        return;
    }

    // Store the received symbol
    auto& block = session.incoming_blocks[block_id];
    if (block.find(symbol_id) == block.end()) {
        block[symbol_id] = std::vector<uint8_t>(payload_start, payload_start + payload_length);
    }

    if (session.reassembled_blocks.count(block_id)) {
        return;
    }
    
    //std::cerr << "[BLOCK SIZE " << block.size() << std::endl;
    
    // Check if we have enough symbols to decode the block
    if (block.size() >= total_expected) {
        const size_t missing_data = count_missing_data_symbols(block, K);
        session.erasure_count += missing_data;

        std::vector<std::vector<uint8_t>> decoded_symbols;
        //d::cerr << "[missing_data " << missing_data << std::endl;
        if (missing_data == 0) {
            decoded_symbols.reserve(K);
            for (size_t i = 0; i < K; ++i) {
                decoded_symbols.push_back(block.at(static_cast<uint16_t>(i)));
            }
        } else {
            decoded_symbols = fec_strategy_->decode(block, K, block_id);
        }

        if (!decoded_symbols.empty()) {
            session.reassembled_blocks[block_id] = std::move(decoded_symbols);
            if (missing_data > 0) {
                session.corrected_blocks++;
            }
            session.incoming_blocks.erase(block_id);
        } else {
            session.failed_blocks++;
            auto* raptorq = dynamic_cast<RaptorQFEC*>(fec_strategy_.get());
            if (raptorq && raptorq->last_decode_status() == "NEED_DATA" && block.size() >= K) {
                std::cout << "[INFO] Block " << block_id
                          << ": K symbols reached but matrix unsolvable. Waiting for parity..." << std::endl;
            }
        }
        write_blocks_to_file(session);
    }
}

void UDPReceiver::force_decode_attempts(FileSession& session,
                                        size_t K,
                                        size_t total_expected,
                                        uint32_t up_to_block_id) {
    bool blocks_decoded = false;
    for (auto it = session.incoming_blocks.begin(); it != session.incoming_blocks.end(); ) {
        const auto& block_id = it->first;
        auto& symbol_map = it->second;

        if (block_id >= up_to_block_id) {
            ++it;
            continue;
        }

        std::cout << "[Warning] Block " << block_id
                  << ": Timeout reached, attempting decode with "
                  << symbol_map.size() << "/" << total_expected << " symbols." << std::endl;

        const size_t missing_data = count_missing_data_symbols(symbol_map, K);
        session.erasure_count += missing_data;

        std::vector<std::vector<uint8_t>> decoded_symbols;
        if (missing_data == 0) {
            decoded_symbols.reserve(K);
            for (size_t i = 0; i < K; ++i) {
                decoded_symbols.push_back(symbol_map.at(static_cast<uint16_t>(i)));
            }
        } else {
            decoded_symbols = fec_strategy_->decode(symbol_map, K, block_id);
        }

        if (!decoded_symbols.empty()) {
            session.reassembled_blocks[block_id] = std::move(decoded_symbols);
            blocks_decoded = true;
            if (missing_data > 0) {
                session.corrected_blocks++;
            }
            it = session.incoming_blocks.erase(it);
        } else {
            session.failed_blocks++;
            auto* raptorq = dynamic_cast<RaptorQFEC*>(fec_strategy_.get());
            if (raptorq && raptorq->last_decode_status() == "NEED_DATA" && symbol_map.size() >= K) {
                std::cout << "[INFO] Block " << block_id
                          << ": K symbols reached but matrix unsolvable. Waiting for parity..." << std::endl;
            }
            ++it;
        }
    }
    if (blocks_decoded) {
        write_blocks_to_file(session);
    }
}

void UDPReceiver::write_blocks_to_file(FileSession& session) {
    if (!session.file_stream.is_open()) {
        return;
    }
    while (session.reassembled_blocks.count(session.next_block_to_write)) {
        const auto& block_to_write = session.reassembled_blocks.at(session.next_block_to_write);
        
//        std::cout << "Writing block " << session.next_block_to_write << " to file." << std::endl;

        for (const auto& symbol : block_to_write) {
            session.file_stream.write(reinterpret_cast<const char*>(symbol.data()), symbol.size());
        }

        session.reassembled_blocks.erase(session.next_block_to_write);
        session.next_block_to_write++;

        if (session.file_stream.is_open() && static_cast<uint64_t>(session.file_stream.tellp()) >= session.total_file_size) {
            std::cout << "[RECEPTION] File complete: " << session.file_name << std::endl;
            session.file_stream.close();
            const std::filesystem::path file_path =
                session.file_path.empty() ? std::filesystem::path(session.file_name) : session.file_path;
            try {
                std::filesystem::resize_file(file_path, session.total_file_size);

                auto perms = static_cast<std::filesystem::perms>(session.permissions);
                std::filesystem::permissions(file_path, perms, std::filesystem::perm_options::replace);

                std::chrono::nanoseconds ns(session.last_write_time);
                std::filesystem::file_time_type ftime(ns);
                std::filesystem::last_write_time(file_path, ftime);
                
            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "Warning: Could not restore file metadata for " 
                          << session.file_name << ". Reason: " << e.what() << std::endl;
            }

            if (log_stream_ && log_stream_->is_open()) {
                const std::string md5 = calculate_md5(file_path.string());
                (*log_stream_) << "[RECEPTION] File: " << session.file_name
                               << " | Size:" << session.total_file_size
                               << " | FEC: Corrected:" << session.corrected_blocks
                               << ", Failed:" << session.failed_blocks
                               << ", Erasures:" << session.erasure_count
                               << " | MD5: " << md5 << "\n";
                log_stream_->flush();
            }
        }
    }
}

} // namespace udpworm
