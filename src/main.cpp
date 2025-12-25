#include "UDPSender.hpp"
#include "UDPReceiver.hpp"
#include "ReedSolomonFEC.hpp"
#include "RaptorQFEC.hpp"
#include "FECTestRunner.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <filesystem>
#include <csignal>
#include <atomic>

// Global flag for handling Ctrl+C
std::atomic<bool> running(true);

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        running = false;
    }
}


void print_usage() {
    std::cerr << "Usage:\n"
              << "  udp_fec_test sender <filepath> <host> <port> <K> <MTU> <delay_us> <loss_rate> <header_flip_rate> <payload_flip_rate> [--fec <rs|raptorq>]\n"
              << "  udp_fec_test receiver <port> <K> <timeout_ms> <output_path> [log_path] [--fec <rs|raptorq>]\n"
              << "  udp_fec_test unit_test <rs|raptorq> all [symbol_size]\n"
              << "\n"
              << "Example Sender:   ./udp_fec_test sender ./test.txt 127.0.0.1 8080 10 1400 100 0.05 0.01 0.02 --fec rs\n"
              << "Example Receiver: ./udp_fec_test receiver 8080 10 500 ./out ./recv.log --fec raptorq\n"
              << "Example Unit Test: ./udp_fec_test unit_test rs all\n"
              << "Example Unit Test: ./udp_fec_test unit_test raptorq all\n"
              << "Tip: Use delay_us >= 50 for local loopback to reduce packet drops.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string mode = argv[1];
    
    // The FEC strategy is instantiated inside the modes where it's used.

    try {
        auto make_fec_strategy = [](const std::string& fec_name, size_t K)
            -> std::unique_ptr<udpworm::IFECStrategy> {
            const size_t M = (K == 50) ? 10 : (K == 100) ? 20 : 4;
            if (fec_name == "rs") {
                return std::make_unique<udpworm::ReedSolomonFEC>(K, M);
            }
            if (fec_name == "raptorq") {
                return std::make_unique<udpworm::RaptorQFEC>(K, M);
            }
            throw std::runtime_error("Unknown FEC type: " + fec_name);
        };

        if (mode == "sender") {
            if (argc < 11) {
                print_usage();
                return 1;
            }
            int argi = 2;
            std::filesystem::path file_path = argv[argi++];
            std::string host = argv[argi++];
            uint16_t port = static_cast<uint16_t>(std::stoul(argv[argi++]));
            size_t K = std::stoul(argv[argi++]);
            size_t mtu = std::stoul(argv[argi++]);
            long long delay_us = std::stoll(argv[argi++]);
            float loss_rate = std::stof(argv[argi++]);
            float header_flip_rate = std::stof(argv[argi++]);
            float payload_flip_rate = std::stof(argv[argi++]);
            std::string fec_name = "rs";

            while (argi < argc) {
                std::string flag = argv[argi++];
                if (flag == "--fec") {
                    if (argi >= argc) {
                        print_usage();
                        return 1;
                    }
                    fec_name = argv[argi++];
                } else {
                    print_usage();
                    return 1;
                }
            }

            if (!std::filesystem::exists(file_path)) {
                throw std::runtime_error("File not found: " + file_path.string());
            }
            
            std::unique_ptr<udpworm::IFECStrategy> fec_strategy = make_fec_strategy(fec_name, K);
            udpworm::UDPSender sender(std::move(fec_strategy), host, port,
                                      std::chrono::microseconds(delay_us), loss_rate,
                                      header_flip_rate, payload_flip_rate);
            std::cout << "SENDER: Using FEC " << fec_name << std::endl;
            std::cout << "SENDER: Sending " << file_path << " to " << host << ":" << port 
                      << " with " << (loss_rate * 100) << "% simulated loss." << std::endl;
            sender.send_file(file_path, K, mtu);

        } else if (mode == "receiver") {
            if (argc < 6) {
                print_usage();
                return 1;
            }
            int argi = 2;
            uint16_t port = static_cast<uint16_t>(std::stoul(argv[argi++]));
            size_t K = std::stoul(argv[argi++]);
            long long timeout_ms = std::stoll(argv[argi++]);
            std::filesystem::path output_path = argv[argi++];
            std::filesystem::path log_path;
            std::string fec_name = "rs";

            while (argi < argc) {
                std::string flag = argv[argi++];
                if (flag == "--fec") {
                    if (argi >= argc) {
                        print_usage();
                        return 1;
                    }
                    fec_name = argv[argi++];
                } else if (log_path.empty()) {
                    log_path = std::filesystem::path(flag);
                } else {
                    print_usage();
                    return 1;
                }
            }
            
            signal(SIGINT, signal_handler);
            signal(SIGTERM, signal_handler);

            std::unique_ptr<udpworm::IFECStrategy> fec_strategy = make_fec_strategy(fec_name, K);
            udpworm::UDPReceiver receiver(port, std::move(fec_strategy), output_path, log_path);
            std::cout << "RECEIVER: Using FEC " << fec_name << std::endl;
            std::cout << "RECEIVER: Listening on port " << port << ". Press Ctrl+C to stop." << std::endl;
            receiver.listen(K, running, std::chrono::milliseconds(timeout_ms));
            std::cout << "\nRECEIVER: Shutting down." << std::endl;
        } else if (mode == "unit_test") {
            if (argc < 4) {
                print_usage();
                return 1;
            }
            std::string fec_name = argv[2];
            std::vector<std::pair<size_t, size_t>> configs;
            size_t symbol_size = 0;

            if ((fec_name == "rs" || fec_name == "raptorq") && std::string(argv[3]) == "all") {
                constexpr size_t kDefaultSymbolSize = 128;
                configs = {{10, 4}, {50, 10}, {100, 20}};
                if (argc == 4) {
                    symbol_size = kDefaultSymbolSize;
                } else if (argc == 5) {
                    symbol_size = std::stoul(argv[4]);
                } else {
                    print_usage();
                    return 1;
                }
            } else {
                print_usage();
                return 1;
            }

            udpworm::FECTestRunner runner;
            const bool ok = runner.run_test(fec_name, configs, symbol_size);
            if (ok) {
                std::cout << "[UNIT TEST] All scenarios passed." << std::endl;
                return 0;
            }
            std::cerr << "[UNIT TEST] One or more scenarios failed." << std::endl;
            return 1;
        } else {
            std::cerr << "Invalid mode: " << mode << "\n";
            print_usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
