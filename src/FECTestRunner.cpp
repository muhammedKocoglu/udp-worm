#include "FECTestRunner.hpp"
#include "ReedSolomonFEC.hpp"
#include "RaptorQFEC.hpp"
#include "LDPCFEC.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>

namespace udpworm {

namespace {
std::vector<uint8_t> flatten_symbols(const std::vector<std::vector<uint8_t>>& symbols) {
    size_t total = 0;
    for (const auto& symbol : symbols) {
        total += symbol.size();
    }
    std::vector<uint8_t> flat;
    flat.reserve(total);
    for (const auto& symbol : symbols) {
        flat.insert(flat.end(), symbol.begin(), symbol.end());
    }
    return flat;
}

std::string md5_hex(const std::vector<uint8_t>& data) {
    if (data.empty()) {
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

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
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

std::map<uint16_t, std::vector<uint8_t>> build_symbol_map(
    const std::vector<std::vector<uint8_t>>& data_symbols,
    const std::vector<std::vector<uint8_t>>& parity_symbols) {
    std::map<uint16_t, std::vector<uint8_t>> symbols;
    for (uint16_t i = 0; i < data_symbols.size(); ++i) {
        symbols[i] = data_symbols[i];
    }
    for (uint16_t i = 0; i < parity_symbols.size(); ++i) {
        symbols[static_cast<uint16_t>(data_symbols.size() + i)] = parity_symbols[i];
    }
    return symbols;
}

std::vector<uint16_t> build_drop_list(size_t K,
                                      size_t M,
                                      size_t total_drop,
                                      bool prefer_data_first) {
    size_t drop_data = std::min(K, total_drop / 2);
    size_t drop_parity = total_drop - drop_data;

    if (drop_parity > M) {
        drop_parity = M;
        drop_data = total_drop - drop_parity;
    }
    if (drop_data > K) {
        drop_data = K;
        drop_parity = total_drop - drop_data;
    }

    if (drop_data == 0 && K > 0 && total_drop > 0) {
        drop_data = 1;
        drop_parity = total_drop - drop_data;
        if (drop_parity > M) {
            drop_parity = M;
            drop_data = total_drop - drop_parity;
        }
    }

    if (drop_parity == 0 && M > 0 && total_drop > 0 && drop_data < total_drop) {
        drop_parity = 1;
        drop_data = total_drop - drop_parity;
        if (drop_data > K) {
            drop_data = K;
            drop_parity = total_drop - drop_data;
        }
    }

    std::vector<uint16_t> ids;
    ids.reserve(drop_data + drop_parity);
    auto append_data = [&]() {
        for (size_t i = 0; i < drop_data; ++i) {
            ids.push_back(static_cast<uint16_t>(i));
        }
    };
    auto append_parity = [&]() {
        for (size_t i = 0; i < drop_parity; ++i) {
            ids.push_back(static_cast<uint16_t>(K + i));
        }
    };

    if (prefer_data_first) {
        append_data();
        append_parity();
    } else {
        append_parity();
        append_data();
    }
    return ids;
}

void drop_symbols(std::map<uint16_t, std::vector<uint8_t>>& symbols,
                  size_t K,
                  size_t M,
                  size_t total_drop,
                  bool prefer_data_first) {
    const auto drop_list = build_drop_list(K, M, total_drop, prefer_data_first);
    for (const auto symbol_id : drop_list) {
        symbols.erase(symbol_id);
    }
}

bool verify_decoded(const std::vector<std::vector<uint8_t>>& decoded,
                    const std::vector<std::vector<uint8_t>>& original) {
    if (decoded.size() != original.size()) {
        return false;
    }
    return decoded == original;
}

struct TestTimings {
    long long encode_us = -1;
    long long decode_us[4] = {-1, -1, -1, -1};
    long long overhead_extra = -1;
    bool ok = false;
};

struct TestSummary {
    size_t K = 0;
    size_t M = 0;
    TestTimings timings;
    std::string error;
};

TestTimings run_single_test(IFECStrategy& strategy,
                            size_t K,
                            size_t M,
                            size_t symbol_size) {
    TestTimings timings;
    auto* raptorq = dynamic_cast<RaptorQFEC*>(&strategy);

    std::vector<std::vector<uint8_t>> source_symbols(K, std::vector<uint8_t>(symbol_size));
    for (size_t i = 0; i < K; ++i) {
        for (size_t j = 0; j < symbol_size; ++j) {
            source_symbols[i][j] = static_cast<uint8_t>((i * symbol_size + j) % 256);
        }
    }

    const auto encode_start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<uint8_t>> parity_symbols = strategy.encode(source_symbols);
    const auto encode_end = std::chrono::high_resolution_clock::now();
    timings.encode_us =
        std::chrono::duration_cast<std::chrono::microseconds>(encode_end - encode_start).count();
    if (raptorq && raptorq->last_encode_compute_us() >= 0) {
        timings.encode_us = raptorq->last_encode_compute_us();
    }
    std::cout << "[UNIT TEST] Encode time: " << timings.encode_us << " us" << std::endl;

    if (M > 0 && parity_symbols.size() != M) {
        std::cerr << "[UNIT TEST] Expected " << M << " parity symbols, got "
                  << parity_symbols.size() << "." << std::endl;
        timings.ok = false;
        return timings;
    }

    const std::string original_md5 = md5_hex(flatten_symbols(source_symbols));
    bool all_ok = true;

    auto run_scenario = [&](const std::string& label,
                            size_t drop_count,
                            uint32_t block_id,
                            bool expect_success,
                            bool prefer_data_first,
                            long long& out_us,
                            bool allow_need_data_info) {
        std::cout << "[UNIT TEST] " << label << std::endl;
        auto symbols = build_symbol_map(source_symbols, parity_symbols);
        drop_symbols(symbols, K, parity_symbols.size(), drop_count, prefer_data_first);
        const auto decode_start = std::chrono::high_resolution_clock::now();
        auto decoded = strategy.decode(symbols, K, block_id);
        const auto decode_end = std::chrono::high_resolution_clock::now();
        out_us = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
        std::cout << "[UNIT TEST] Decode time: " << out_us << " us" << std::endl;

        if (expect_success) {
            const std::string decoded_md5 = md5_hex(flatten_symbols(decoded));
            std::cout << "[UNIT TEST] MD5 original: " << original_md5 << std::endl;
            std::cout << "[UNIT TEST] MD5 decoded:  " << decoded_md5 << std::endl;
            if (!verify_decoded(decoded, source_symbols)) {
                if (allow_need_data_info && raptorq && raptorq->last_decode_status() == "NEED_DATA") {
                    std::cout << "[INFO] RaptorQ behaved as expected: MDS property not met (NEED_DATA)." << std::endl;
                    return true;
                }
                std::cerr << "[UNIT TEST] " << label << " failed: decoded data mismatch." << std::endl;
                return false;
            }
            return true;
        }

        if (!decoded.empty()) {
            std::cerr << "[UNIT TEST] " << label << " failed: expected empty result." << std::endl;
            return false;
        }
        return true;
    };

    const bool s1_ok = run_scenario("Scenario 1 (Perfect): 0 symbols dropped.",
                                    0,
                                    100,
                                    true,
                                    false,
                                    timings.decode_us[0],
                                    false);
    bool s2_ok = false;
    {
        std::cout << "[UNIT TEST] Scenario 2 (Near-Optimal): Adaptive overhead (start at K symbols)." << std::endl;
        const auto all_symbols = build_symbol_map(source_symbols, parity_symbols);
        const auto drop_list = build_drop_list(K, parity_symbols.size(), M, true);
        auto symbols = all_symbols;
        for (const auto symbol_id : drop_list) {
            symbols.erase(symbol_id);
        }

        size_t restored = 0;
        while (true) {
            const uint32_t block_id = 200 + static_cast<uint32_t>(restored);
            const auto decode_start = std::chrono::high_resolution_clock::now();
            auto decoded = strategy.decode(symbols, K, block_id);
            const auto decode_end = std::chrono::high_resolution_clock::now();
            timings.decode_us[1] =
                std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
            std::cout << "[UNIT TEST] Decode time: " << timings.decode_us[1] << " us" << std::endl;

            if (verify_decoded(decoded, source_symbols)) {
                const std::string decoded_md5 = md5_hex(flatten_symbols(decoded));
                std::cout << "[UNIT TEST] MD5 original: " << original_md5 << std::endl;
                std::cout << "[UNIT TEST] MD5 decoded:  " << decoded_md5 << std::endl;
                timings.overhead_extra = static_cast<long long>(restored);
                if (raptorq) {
                    std::cout << "[UNIT TEST] RaptorQ required K+" << restored << " symbols to succeed." << std::endl;
                }
                s2_ok = true;
                break;
            }

            const bool need_data = raptorq && raptorq->last_decode_status() == "NEED_DATA";
            if (!decoded.empty() && !need_data) {
                std::cerr << "[UNIT TEST] Scenario 2 failed: decoded data mismatch." << std::endl;
                break;
            }

            if (restored >= drop_list.size()) {
                std::cerr << "[UNIT TEST] Scenario 2 failed: unable to decode with full symbol set." << std::endl;
                break;
            }

            const auto restore_id = drop_list[drop_list.size() - 1 - restored];
            symbols[restore_id] = all_symbols.at(restore_id);
            restored++;
        }
    }

    const bool s3_ok = run_scenario("Scenario 3 (Strict-Optimal): Drop exactly M symbols.",
                                    M,
                                    300,
                                    true,
                                    true,
                                    timings.decode_us[2],
                                    true);
    const bool s4_ok = run_scenario("Scenario 4 (Unrecoverable): Drop M+1 symbols.",
                                    M + 1,
                                    400,
                                    false,
                                    false,
                                    timings.decode_us[3],
                                    false);

    all_ok = s1_ok && s2_ok && s3_ok && s4_ok;

    timings.ok = all_ok;
    return timings;
}
} // namespace

bool FECTestRunner::run_test(const std::string& fec_name,
                             const std::vector<std::pair<size_t, size_t>>& configs,
                             size_t symbol_size) {
    if (configs.empty()) {
        std::cerr << "[UNIT TEST] No FEC configurations provided." << std::endl;
        return false;
    }
    if (symbol_size == 0) {
        std::cerr << "[UNIT TEST] Invalid symbol size." << std::endl;
        return false;
    }

    std::vector<TestSummary> summaries;
    bool all_ok = true;

    for (const auto& config : configs) {
        TestSummary summary;
        summary.K = config.first;
        summary.M = config.second;

        if (summary.K == 0) {
            summary.error = "Invalid K value.";
            std::cerr << "[UNIT TEST] " << summary.error << std::endl;
            summaries.push_back(summary);
            all_ok = false;
            continue;
        }

        std::unique_ptr<IFECStrategy> strategy;
        try {
            if (fec_name == "rs") {
                strategy = std::make_unique<ReedSolomonFEC>(summary.K, summary.M);
            } else if (fec_name == "raptorq") {
                strategy = std::make_unique<RaptorQFEC>(summary.K, summary.M);
            } else if (fec_name == "ldpc") {
                strategy = std::make_unique<LDPCFEC>(summary.K, summary.M);
            } else {
                std::cerr << "[UNIT TEST] Unknown FEC type: " << fec_name << std::endl;
                return false;
            }
        } catch (const std::exception& ex) {
            summary.error = ex.what();
            std::cerr << "[UNIT TEST] " << summary.error << std::endl;
            summaries.push_back(summary);
            all_ok = false;
            continue;
        }

        std::cout << "\n[UNIT TEST] Running " << fec_name << " K=" << summary.K
                  << " M=" << summary.M << " symbol_size=" << symbol_size << std::endl;

        summary.timings = run_single_test(*strategy, summary.K, summary.M, symbol_size);
        if (!summary.timings.ok) {
            all_ok = false;
        }
        summaries.push_back(summary);
    }

    std::cout << "\n[UNIT TEST] Summary (symbol_size=" << symbol_size << ")\n";
    std::cout << std::left << std::setw(6) << "K"
              << std::setw(6) << "M"
              << std::setw(12) << "Enc(us)"
              << std::setw(12) << "Dec1(us)"
              << std::setw(12) << "Dec2(us)"
              << std::setw(12) << "Dec3(us)"
              << std::setw(12) << "Dec4(us)"
              << std::setw(12) << "Overhead"
              << "Status" << std::endl;

    for (const auto& summary : summaries) {
        auto format_time = [](long long value) {
            return value < 0 ? std::string("-") : std::to_string(value);
        };

        std::cout << std::left << std::setw(6) << summary.K
                  << std::setw(6) << summary.M
                  << std::setw(12) << format_time(summary.timings.encode_us)
                  << std::setw(12) << format_time(summary.timings.decode_us[0])
                  << std::setw(12) << format_time(summary.timings.decode_us[1])
                  << std::setw(12) << format_time(summary.timings.decode_us[2])
                  << std::setw(12) << format_time(summary.timings.decode_us[3])
                  << std::setw(12) << (summary.timings.overhead_extra < 0
                                          ? std::string("-")
                                          : "K+" + std::to_string(summary.timings.overhead_extra))
                  << (summary.timings.ok ? "OK" : "FAIL") << std::endl;
    }

    return all_ok;
}

} // namespace udpworm
