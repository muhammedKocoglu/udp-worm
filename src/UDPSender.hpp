#pragma once

#include "IFECStrategy.hpp"
#include "Protocol.hpp"
#include <memory>
#include <string>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <random>
#include <boost/asio.hpp>

namespace udpworm {

namespace asio = boost::asio;
using boost::asio::ip::udp;

class UDPSender {
public:
    UDPSender(std::unique_ptr<IFECStrategy> fec_strategy, 
              const std::string& host, 
              uint16_t port,
              std::chrono::microseconds packet_delay,
              float loss_rate,
              float header_bit_flip_rate,
              float payload_bit_flip_rate,
              std::string fec_name = "unknown");
    
    // K is the number of data symbols per block for the FEC scheme.
    void send_file(const std::filesystem::path& file_path, size_t K, size_t mtu);

private:
    std::unique_ptr<IFECStrategy> fec_strategy_;
    std::chrono::microseconds packet_delay_;
    float loss_rate_;
    float header_bit_flip_rate_;
    float payload_bit_flip_rate_;

    asio::io_context io_context_;
    udp::socket socket_;
    udp::resolver::results_type endpoints_;

    std::mt19937 random_generator_;
    std::uniform_real_distribution<float> distribution_;

    long long total_encode_us_ = 0;
    long long total_send_us_ = 0;
    size_t packets_dropped_ = 0;
    size_t header_flips_ = 0;
    size_t payload_flips_ = 0;
    size_t total_blocks_ = 0;
    std::string fec_name_ = "unknown";

    void send_packet(const PacketHeader& header, std::span<const uint8_t> payload);
    void inject_bit_flip(uint8_t* data, size_t size);
};

} // namespace udpworm
