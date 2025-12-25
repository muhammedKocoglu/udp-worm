#include "RaptorQFEC.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <span>
#include <string>
#include <vector>
#include <sstream>
#ifdef RQ_HEADER_ONLY
#include <RaptorQ/v1/caches.ipp>
#endif

namespace udpworm {

namespace {
RaptorQ__v1::Block_Size block_size_for_k(size_t symbols) {
    if (symbols == 0) {
        return static_cast<RaptorQ__v1::Block_Size>(0);
    }
    for (const auto& block : *RaptorQ__v1::blocks) {
        if (static_cast<uint16_t>(block) >= symbols) {
            return block;
        }
    }
    return static_cast<RaptorQ__v1::Block_Size>(0);
}

std::string format_symbol_id_list(const std::map<uint16_t, std::vector<uint8_t>>& symbols) {
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& pair : symbols) {
        if (!first) {
            oss << ", ";
        }
        oss << pair.first;
        first = false;
    }
    oss << "]";
    return oss.str();
}

std::string format_repair_symbol_id_list(const std::map<uint16_t, std::vector<uint8_t>>& symbols,
                                         uint16_t data_symbol_count) {
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& pair : symbols) {
        if (pair.first < data_symbol_count) {
            continue;
        }
        if (!first) {
            oss << ", ";
        }
        oss << pair.first;
        first = false;
    }
    oss << "]";
    return oss.str();
}

const char* decoder_result_to_string(RaptorQ__v1::Decoder_Result result) {
    switch (result) {
        case RaptorQ__v1::Decoder_Result::DECODED:
            return "DECODED";
        case RaptorQ__v1::Decoder_Result::STOPPED:
            return "STOPPED";
        case RaptorQ__v1::Decoder_Result::CAN_RETRY:
            return "CAN_RETRY";
        case RaptorQ__v1::Decoder_Result::NEED_DATA:
            return "NEED_DATA";
        default:
            return "UNKNOWN";
    }
}

const char* error_to_string(RaptorQ__v1::Error err) {
    switch (err) {
        case RaptorQ__v1::Error::NONE:
            return "NONE";
        case RaptorQ__v1::Error::NOT_NEEDED:
            return "NOT_NEEDED";
        case RaptorQ__v1::Error::WRONG_INPUT:
            return "WRONG_INPUT";
        case RaptorQ__v1::Error::NEED_DATA:
            return "NEED_DATA";
        case RaptorQ__v1::Error::WORKING:
            return "WORKING";
        case RaptorQ__v1::Error::INITIALIZATION:
            return "INITIALIZATION";
        case RaptorQ__v1::Error::EXITING:
            return "EXITING";
        default:
            return "UNKNOWN";
    }
}

void log_decode_failure(uint32_t block_id,
                        size_t required_symbols,
                        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
                        const char* cause) {
    std::cerr << "[FEC] Block " << block_id << ": Decode failed. Required " << required_symbols
              << ", but only " << received_symbols.size() << " symbols present: "
              << format_symbol_id_list(received_symbols);
    if (cause && *cause) {
        std::cerr << ". Cause: " << cause;
    }
    std::cerr << std::endl;
}
} // namespace

RaptorQFEC::RaptorQFEC(size_t data_symbols, size_t parity_symbols)
    : data_symbols_(data_symbols),
      parity_symbols_(parity_symbols) {}

std::vector<std::vector<uint8_t>> RaptorQFEC::encode(const std::vector<std::vector<uint8_t>>& source_symbols) {
    if (source_symbols.empty()) {
        return {};
    }

    const size_t K = source_symbols.size();
    if (data_symbols_ != 0 && K != data_symbols_) {
        return {};
    }
    const size_t T = source_symbols[0].size();
    if (T == 0) {
        return {};
    }

    for (const auto& symbol : source_symbols) {
        if (symbol.size() != T) {
            return {};
        }
    }

    std::vector<uint8_t> source_data;
    source_data.reserve(K * T);
    for (const auto& symbol : source_symbols) {
        source_data.insert(source_data.end(), symbol.begin(), symbol.end());
    }

    const auto block_size = block_size_for_k(K);
    if (block_size == static_cast<RaptorQ__v1::Block_Size>(0)) {
        return {};
    }

    using Encoder = RaptorQ__v1::Encoder<uint8_t*, uint8_t*>;
    Encoder encoder(block_size, T);
    if (!encoder) {
        return {};
    }
    uint8_t* data_start = source_data.data();
    uint8_t* data_end = data_start + source_data.size();
    encoder.set_data(data_start, data_end);
    if (!encoder.precompute_sync() || !encoder.compute_sync()) {
        return {};
    }

    const size_t M = parity_symbols_;
    std::vector<std::vector<uint8_t>> parity_symbols;
    parity_symbols.reserve(M);

    for (uint32_t i = 0; i < M; ++i) {
        const uint32_t esi = static_cast<uint32_t>(K + i);
        std::vector<uint8_t> symbol(T);
        uint8_t* out = symbol.data();
        uint8_t* out_end = out + symbol.size();
        const size_t written = encoder.encode(out, out_end, esi);
        if (written != symbol.size()) {
            return {};
        }
        parity_symbols.push_back(std::move(symbol));
    }

    return parity_symbols;
}

std::vector<std::vector<uint8_t>> RaptorQFEC::decode(
    const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
    size_t K_data_symbols,
    uint32_t block_id) {

    last_decode_status_.clear();

    if (received_symbols.empty() || K_data_symbols == 0) {
        last_decode_status_ = "INVALID_INPUT";
        log_decode_failure(block_id, K_data_symbols, received_symbols, "empty symbols or K=0");
        return {};
    }
    if (data_symbols_ != 0 && K_data_symbols != data_symbols_) {
        last_decode_status_ = "K_MISMATCH";
        log_decode_failure(block_id, data_symbols_, received_symbols, "K mismatch");
        return {};
    }

    const size_t T = received_symbols.begin()->second.size();
    if (T == 0) {
        last_decode_status_ = "INVALID_SYMBOL_SIZE";
        log_decode_failure(block_id, K_data_symbols, received_symbols, "symbol size is 0");
        return {};
    }

    for (const auto& pair : received_symbols) {
        if (pair.second.size() != T) {
            last_decode_status_ = "INVALID_SYMBOL_SIZE";
            log_decode_failure(block_id, K_data_symbols, received_symbols, "symbol size mismatch");
            return {};
        }
    }

    if (received_symbols.size() < K_data_symbols) {
        last_decode_status_ = "INSUFFICIENT_SYMBOLS";
        log_decode_failure(block_id, K_data_symbols, received_symbols, "insufficient symbols");
        return {};
    }

    bool all_data_present = true;
    for (size_t i = 0; i < K_data_symbols; ++i) {
        if (received_symbols.find(static_cast<uint16_t>(i)) == received_symbols.end()) {
            all_data_present = false;
            break;
        }
    }
    if (all_data_present) {
        std::vector<std::vector<uint8_t>> direct_data(K_data_symbols);
        for (size_t i = 0; i < K_data_symbols; ++i) {
            direct_data[i] = received_symbols.at(static_cast<uint16_t>(i));
        }
        return direct_data;
    }
    const bool math_used = !all_data_present;

    const auto block_size = block_size_for_k(K_data_symbols);
    if (block_size == static_cast<RaptorQ__v1::Block_Size>(0)) {
        last_decode_status_ = "UNSUPPORTED_BLOCK_SIZE";
        log_decode_failure(block_id, K_data_symbols, received_symbols, "unsupported block size");
        return {};
    }

    using Decoder = RaptorQ__v1::Decoder<uint8_t*, uint8_t*>;
    Decoder decoder(block_size, T, RaptorQ__v1::Dec_Report::COMPLETE);
    if (!decoder) {
        last_decode_status_ = "DECODER_INIT_FAILED";
        log_decode_failure(block_id, K_data_symbols, received_symbols, "decoder initialization failed");
        return {};
    }

    for (const auto& pair : received_symbols) {
        const uint32_t esi = static_cast<uint32_t>(pair.first);
        uint8_t* it_start = const_cast<uint8_t*>(pair.second.data());
        uint8_t* it_end = it_start + pair.second.size();
        const auto err = decoder.add_symbol(it_start, it_end, esi);
        if (err != RaptorQ__v1::Error::NONE && err != RaptorQ__v1::Error::NOT_NEEDED) {
            std::ostringstream cause;
            cause << "add_symbol ESI " << esi << " (" << error_to_string(err) << ")";
            last_decode_status_ = error_to_string(err);
            log_decode_failure(block_id, K_data_symbols, received_symbols, cause.str().c_str());
            return {};
        }
    }
    decoder.end_of_input(RaptorQ__v1::Fill_With_Zeros::NO);

    auto report = decoder.decode_once();
    while (report == RaptorQ__v1::Decoder_Result::CAN_RETRY) {
        report = decoder.decode_once();
    }
    if (report != RaptorQ__v1::Decoder_Result::DECODED) {
        std::ostringstream cause;
        cause << "decode result " << decoder_result_to_string(report);
        last_decode_status_ = decoder_result_to_string(report);
        log_decode_failure(block_id, K_data_symbols, received_symbols, cause.str().c_str());
        return {};
    }

    std::vector<uint8_t> output(K_data_symbols * T);
    uint8_t* out_it = output.data();
    uint8_t* out_end = out_it + output.size();
    const auto decoded = decoder.decode_bytes(out_it, out_end, 0, 0);
    if (decoded.written != output.size()) {
        std::ostringstream cause;
        cause << "decode_bytes wrote " << decoded.written << "/" << output.size();
        last_decode_status_ = "DECODE_INCOMPLETE";
        log_decode_failure(block_id, K_data_symbols, received_symbols, cause.str().c_str());
        return {};
    }

    if (math_used) {
        std::cout << "[FEC] Block " << block_id << ": Fixed using repair symbols "
                  << format_repair_symbol_id_list(received_symbols, static_cast<uint16_t>(K_data_symbols))
                  << "." << std::endl;
    }

    std::vector<std::vector<uint8_t>> decoded_symbols;
    decoded_symbols.reserve(K_data_symbols);
    for (size_t i = 0; i < K_data_symbols; ++i) {
        const size_t offset = i * T;
        decoded_symbols.emplace_back(output.begin() + offset, output.begin() + offset + T);
    }

    last_decode_status_ = "DECODED";
    return decoded_symbols;
}

} // namespace udpworm
