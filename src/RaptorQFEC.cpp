#include "RaptorQFEC.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <span>
#include <string>
#include <vector>
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

} // namespace

RaptorQFEC::RaptorQFEC(size_t data_symbols, size_t parity_symbols)
    : data_symbols_(data_symbols),
      parity_symbols_(parity_symbols) {}

std::vector<std::vector<uint8_t>> RaptorQFEC::encode(const std::vector<std::vector<uint8_t>>& source_symbols) {
    if (source_symbols.empty()) {
        std::cerr << "[ERROR] RaptorQ encode failed: no source symbols." << std::endl;
        return {};
    }

    const size_t K = source_symbols.size();
    if (data_symbols_ != 0 && K != data_symbols_) {
        std::cerr << "[ERROR] RaptorQ encode failed: K mismatch (expected "
                  << data_symbols_ << ", got " << K << ")." << std::endl;
        return {};
    }
    const size_t T = source_symbols[0].size();
    // Note: libRaptorQ cached mode expects symbol sizes aligned (often 4 or 8 bytes).
    if (T == 0) {
        std::cerr << "[ERROR] RaptorQ encode failed: symbol size is 0." << std::endl;
        return {};
    }

    for (const auto& symbol : source_symbols) {
        if (symbol.size() != T) {
            std::cerr << "[ERROR] RaptorQ encode failed: symbol size mismatch." << std::endl;
            return {};
        }
    }

    const auto block_size = block_size_for_k(K);
    if (block_size == static_cast<RaptorQ__v1::Block_Size>(0)) {
        std::cerr << "[ERROR] RaptorQ encode failed: unsupported block size." << std::endl;
        return {};
    }

    last_encode_compute_us_ = -1;
    if (!cached_encoder_ || last_K_ != K || last_symbol_size_ != T) {
        cached_encoder_ = std::make_unique<Encoder>(block_size, T);
        if (!*cached_encoder_) {
            std::cerr << "[ERROR] RaptorQ encode failed: encoder init failed." << std::endl;
            cached_encoder_.reset();
            return {};
        }
        if (!cached_encoder_->precompute_sync()) {
            std::cerr << "[ERROR] RaptorQ encode failed: precompute_sync failed." << std::endl;
            cached_encoder_.reset();
            return {};
        }
        last_K_ = K;
        last_symbol_size_ = T;
    }

    // RaptorQ keeps pointers to the source buffer; store it on the instance to
    // satisfy source-data lifetime. The matrix is cached (amortized O(1)), but
    // intermediate symbols must be recomputed (O(K)) for each new block.
    const size_t total_bytes = K * T;
    if (persistent_buffer_.capacity() < total_bytes) {
        persistent_buffer_.reserve(total_bytes);
    }
    if (persistent_buffer_.size() != total_bytes) {
        persistent_buffer_.resize(total_bytes);
    }
    size_t offset = 0;
    for (const auto& symbol : source_symbols) {
        std::memcpy(persistent_buffer_.data() + offset, symbol.data(), T);
        offset += T;
    }

    cached_encoder_->clear_data();
    uint8_t* data_start = persistent_buffer_.data();
    uint8_t* data_end = data_start + persistent_buffer_.size();
    cached_encoder_->set_data(data_start, data_end);
    const auto compute_start = std::chrono::high_resolution_clock::now();
    if (!cached_encoder_->compute_sync()) {
        std::cerr << "[ERROR] RaptorQ encode failed: compute_sync failed." << std::endl;
        return {};
    }
    const auto compute_end = std::chrono::high_resolution_clock::now();
    last_encode_compute_us_ = std::chrono::duration_cast<std::chrono::microseconds>(
                                  compute_end - compute_start)
                                  .count();

    const size_t M = parity_symbols_;
    std::vector<std::vector<uint8_t>> parity_symbols;
    parity_symbols.reserve(M);

    for (uint32_t i = 0; i < M; ++i) {
        const uint32_t esi = static_cast<uint32_t>(K + i);
        std::vector<uint8_t> symbol(T);
        uint8_t* out = symbol.data();
        uint8_t* out_end = out + symbol.size();
        size_t written = cached_encoder_->encode(out, out_end, esi);
        if (written == 0) {
            if (!cached_encoder_->precompute_sync()) {
                std::cerr << "[ERROR] RaptorQ encode failed: precompute_sync retry failed." << std::endl;
                return {};
            }
            if (!cached_encoder_->compute_sync()) {
                std::cerr << "[ERROR] RaptorQ encode failed: compute_sync retry failed." << std::endl;
                return {};
            }
            written = cached_encoder_->encode(out, out_end, esi);
            if (written == 0) {
                const auto err = cached_encoder_->compute().get();
                std::cerr << "[ERROR] RaptorQ encode failed for ESI " << esi
                          << " (" << error_to_string(err) << ")" << std::endl;
                return {};
            }
        }
        if (written != symbol.size()) {
            std::cerr << "[ERROR] RaptorQ encode failed for ESI " << esi << std::endl;
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
        return {};
    }
    if (data_symbols_ != 0 && K_data_symbols != data_symbols_) {
        last_decode_status_ = "K_MISMATCH";
        return {};
    }

    const size_t T = received_symbols.begin()->second.size();
    if (T == 0) {
        last_decode_status_ = "INVALID_SYMBOL_SIZE";
        return {};
    }

    for (const auto& pair : received_symbols) {
        if (pair.second.size() != T) {
            last_decode_status_ = "INVALID_SYMBOL_SIZE";
            return {};
        }
    }

    if (received_symbols.size() < K_data_symbols) {
        last_decode_status_ = "INSUFFICIENT_SYMBOLS";
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
    const auto block_size = block_size_for_k(K_data_symbols);
    if (block_size == static_cast<RaptorQ__v1::Block_Size>(0)) {
        last_decode_status_ = "UNSUPPORTED_BLOCK_SIZE";
        return {};
    }

    using Decoder = RaptorQ__v1::Decoder<uint8_t*, uint8_t*>;
    Decoder decoder(block_size, T, RaptorQ__v1::Dec_Report::COMPLETE);
    if (!decoder) {
        last_decode_status_ = "DECODER_INIT_FAILED";
        return {};
    }

    for (const auto& pair : received_symbols) {
        const uint32_t esi = static_cast<uint32_t>(pair.first);
        uint8_t* it_start = const_cast<uint8_t*>(pair.second.data());
        uint8_t* it_end = it_start + pair.second.size();
        const auto err = decoder.add_symbol(it_start, it_end, esi);
        if (err != RaptorQ__v1::Error::NONE && err != RaptorQ__v1::Error::NOT_NEEDED) {
            last_decode_status_ = error_to_string(err);
            return {};
        }
    }
    decoder.end_of_input(RaptorQ__v1::Fill_With_Zeros::NO);

    auto report = decoder.decode_once();
    while (report == RaptorQ__v1::Decoder_Result::CAN_RETRY) {
        report = decoder.decode_once();
    }
    if (report != RaptorQ__v1::Decoder_Result::DECODED) {
        last_decode_status_ = decoder_result_to_string(report);
        return {};
    }

    std::vector<uint8_t> output(K_data_symbols * T);
    uint8_t* out_it = output.data();
    uint8_t* out_end = out_it + output.size();
    const auto decoded = decoder.decode_bytes(out_it, out_end, 0, 0);
    if (decoded.written != output.size()) {
        last_decode_status_ = "DECODE_INCOMPLETE";
        return {};
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
