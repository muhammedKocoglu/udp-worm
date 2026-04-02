#include "UDPSender.hpp"
#include "FilePacketizer.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstddef>
#include <vector>
#include <cstring> // for strncpy
#include <stdexcept>
#include <algorithm> // for std::min
#include <random>

namespace udpworm {

UDPSender::UDPSender(std::unique_ptr<IFECStrategy> fec_strategy, 
                     const std::string& host, 
                     uint16_t port,
                     std::chrono::microseconds packet_delay,
                     float loss_rate,
                     float header_bit_flip_rate,
                     float payload_bit_flip_rate,
                     std::string fec_name)
    : fec_strategy_(std::move(fec_strategy)),
      packet_delay_(packet_delay),
      loss_rate_(loss_rate),
      header_bit_flip_rate_(header_bit_flip_rate),
      payload_bit_flip_rate_(payload_bit_flip_rate),
      io_context_(),
      socket_(io_context_, udp::endpoint(udp::v4(), 0)),
      distribution_(0.0f, 1.0f),
      fec_name_(std::move(fec_name)) {
    
    boost::system::error_code ec;
    socket_.set_option(asio::socket_base::send_buffer_size(8 * 1024 * 1024), ec);
    if (ec) {
        std::cerr << "Warning: Failed to set send buffer size: " << ec.message() << std::endl;
    }
    socket_.set_option(asio::socket_base::receive_buffer_size(8 * 1024 * 1024), ec);
    if (ec) {
        std::cerr << "Warning: Failed to set receive buffer size: " << ec.message() << std::endl;
    }

    // Seed the random number generator
    std::random_device rd;
    random_generator_.seed(rd());

    udp::resolver resolver(io_context_);
    endpoints_ = resolver.resolve(udp::v4(), host, std::to_string(port));
}

void UDPSender::send_file(const std::filesystem::path& file_path, size_t K, size_t mtu) {
    if (K == 0) {
        throw std::invalid_argument("Number of data symbols (K) cannot be zero.");
    }
    
    FilePacketizer packetizer(file_path);

    const size_t header_bytes = sizeof(PacketHeader) + (2 * sizeof(MiniHeader));
    const size_t symbol_payload_size = mtu > (header_bytes + sizeof(uint32_t))
        ? mtu - header_bytes - sizeof(uint32_t)
        : 0;
    if (symbol_payload_size == 0) {
        throw std::runtime_error("MTU is too small for packet headers and payload CRC.");
    }

    PacketHeader header;
    header.file_id = packetizer.get_file_id();
    header.total_file_size = packetizer.get_total_file_size();
    header.permissions = packetizer.get_permissions();
    header.last_write_time = packetizer.get_last_write_time();
    
    // Safely copy filename
    std::strncpy(header.file_name, packetizer.get_file_name().c_str(), MAX_FILENAME_SIZE - 1);
    header.file_name[MAX_FILENAME_SIZE - 1] = '\0';

    uint32_t block_id = 0;

    total_encode_us_ = 0;
    total_send_us_ = 0;
    packets_dropped_ = 0;
    header_flips_ = 0;
    payload_flips_ = 0;
    total_blocks_ = 0;

    uint64_t total_payload_bytes = 0;
    const auto transfer_start = std::chrono::high_resolution_clock::now();

    while (true) {
        std::vector<std::vector<uint8_t>> data_symbols = packetizer.get_next_block(K, symbol_payload_size);
        if (data_symbols.empty()) {
            break; // We are done.
        }

        header.block_id = block_id;

        // --- Encode to get parity symbols ---
        const auto encode_start = std::chrono::high_resolution_clock::now();
        std::vector<std::vector<uint8_t>> parity_symbols = fec_strategy_->encode(data_symbols);
        const auto encode_end = std::chrono::high_resolution_clock::now();
        total_encode_us_ += std::chrono::duration_cast<std::chrono::microseconds>(
                                encode_end - encode_start)
                                .count();

        // --- Send Data Symbols ---
        uint16_t symbol_id = 0;
        for (const auto& symbol : data_symbols) {
            const auto send_start = std::chrono::high_resolution_clock::now();
            header.symbol_id = symbol_id++;
            send_packet(header, symbol);
            if (packet_delay_.count() > 0) {
                const auto deadline = send_start + packet_delay_;
                while (std::chrono::high_resolution_clock::now() < deadline) {
                    std::this_thread::yield();
                }
            }
            const auto send_end = std::chrono::high_resolution_clock::now();
            total_send_us_ += std::chrono::duration_cast<std::chrono::microseconds>(
                                  send_end - send_start)
                                  .count();
        }

        // --- Send Parity Symbols ---
        for (const auto& symbol : parity_symbols) {
            const auto send_start = std::chrono::high_resolution_clock::now();
            header.symbol_id = symbol_id++;
            send_packet(header, symbol);
            if (packet_delay_.count() > 0) {
                const auto deadline = send_start + packet_delay_;
                while (std::chrono::high_resolution_clock::now() < deadline) {
                    std::this_thread::yield();
                }
            }
            const auto send_end = std::chrono::high_resolution_clock::now();
            total_send_us_ += std::chrono::duration_cast<std::chrono::microseconds>(
                                  send_end - send_start)
                                  .count();
        }

        std::cout << "Sent block " << block_id << " ( " << symbol_id << " total symbols)" << std::endl;
        total_payload_bytes += static_cast<uint64_t>(data_symbols.size() + parity_symbols.size()) *
                               static_cast<uint64_t>(symbol_payload_size);
        total_blocks_++;
        block_id++;
    }

    const auto transfer_end = std::chrono::high_resolution_clock::now();
    const auto total_tx_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                 transfer_end - transfer_start)
                                 .count();
    const double total_tx_s = total_tx_us > 0 ? static_cast<double>(total_tx_us) / 1'000'000.0 : 0.0;
    const double total_mb = static_cast<double>(total_payload_bytes) / (1024.0 * 1024.0);
    const double throughput = total_tx_s > 0.0 ? (total_mb / total_tx_s) : 0.0;
    const long long avg_encode_us =
        total_blocks_ > 0 ? (total_encode_us_ / static_cast<long long>(total_blocks_)) : 0;

    std::ostringstream stats;
    stats << "[SENDER STATS]\n"
          << "FEC Strategy: " << fec_name_ << "\n"
          << "Total Blocks: " << total_blocks_ << "\n"
          << "Total Encoding Time: " << total_encode_us_ << " us (avg "
          << avg_encode_us << " us/block)\n"
          << "Total Transmission Time: " << total_tx_us << " us\n"
          << "Effective Throughput: " << std::fixed << std::setprecision(2)
          << throughput << " MB/s\n"
          << "Simulated Chaos: Drops=" << packets_dropped_
          << ", HeaderFlips=" << header_flips_
          << ", PayloadFlips=" << payload_flips_ << "\n";

    std::cout << stats.str();
}

void UDPSender::send_packet(const PacketHeader& header, std::span<const uint8_t> payload) {
    // Simulate packet loss
    if (loss_rate_ > 0 && distribution_(random_generator_) < loss_rate_) {
        packets_dropped_++;
        std::cout << "[Simulated Loss] Dropping Block: " << header.block_id 
                  << ", Symbol: " << header.symbol_id << std::endl;
        return; // Drop the packet
    }

    PacketHeader header_with_crc = header;
    boost::crc_32_type crc;
    crc.process_bytes(&header_with_crc, offsetof(PacketHeader, header_crc));
    header_with_crc.header_crc = crc.checksum();

    MiniHeader mini_header{};
    mini_header.file_id = header_with_crc.file_id;
    mini_header.block_id = header_with_crc.block_id;
    mini_header.symbol_id = header_with_crc.symbol_id;
    boost::crc_32_type mini_crc;
    mini_crc.process_bytes(&mini_header, offsetof(MiniHeader, mini_crc));
    mini_header.mini_crc = mini_crc.checksum();

    MiniHeader mini_header_backup = mini_header;

    if (header_bit_flip_rate_ > 0.0f && distribution_(random_generator_) < header_bit_flip_rate_) {
        header_flips_++;
        inject_bit_flip(reinterpret_cast<uint8_t*>(&header_with_crc), sizeof(header_with_crc));
        std::cout << "[Chaos] Injected bit-flip into Header for Block " << header.block_id
                  << ", Symbol " << header.symbol_id << std::endl;
    }

    boost::crc_32_type payload_crc_calc;
    payload_crc_calc.process_bytes(payload.data(), payload.size());
    const uint32_t payload_crc = payload_crc_calc.checksum();

    const uint8_t* payload_data = payload.data();
    size_t payload_size = payload.size();
    std::vector<uint8_t> payload_copy;
    if (payload_bit_flip_rate_ > 0.0f && distribution_(random_generator_) < payload_bit_flip_rate_) {
        payload_flips_++;
        payload_copy.assign(payload.begin(), payload.end());
        inject_bit_flip(payload_copy.data(), payload_copy.size());
        payload_data = payload_copy.data();
        payload_size = payload_copy.size();
        std::cout << "[Chaos] Injected bit-flip into Payload for Block " << header.block_id
                  << ", Symbol " << header.symbol_id << std::endl;
    }

    std::vector<asio::const_buffer> buffers;
    buffers.reserve(5);
    buffers.emplace_back(asio::buffer(&header_with_crc, sizeof(header_with_crc)));
    buffers.emplace_back(asio::buffer(&mini_header, sizeof(mini_header)));
    buffers.emplace_back(asio::buffer(&mini_header_backup, sizeof(mini_header_backup)));
    buffers.emplace_back(asio::buffer(payload_data, payload_size));
    buffers.emplace_back(asio::buffer(&payload_crc, sizeof(payload_crc)));

    try {
        socket_.send_to(buffers, *endpoints_.begin());
    } catch (const boost::system::system_error& ex) {
        std::cerr << "Error sending packet: " << ex.what() << std::endl;
    }
}

void UDPSender::inject_bit_flip(uint8_t* data, size_t size) {
    if (size == 0) {
        return;
    }

    std::uniform_int_distribution<size_t> byte_dist(0, size - 1);
    std::uniform_int_distribution<int> bit_dist(0, 7);
    const size_t byte_index = byte_dist(random_generator_);
    const int bit_index = bit_dist(random_generator_);
    data[byte_index] ^= static_cast<uint8_t>(1u << bit_index);
}

} // namespace udpworm
