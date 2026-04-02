#pragma once

#include "IFECStrategy.hpp"
#ifndef RQ_HEADER_ONLY
#define RQ_HEADER_ONLY
#endif
#include <RaptorQ/v1/RaptorQ.hpp>
#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace udpworm {

class RaptorQFEC : public IFECStrategy {
public:
    RaptorQFEC(size_t data_symbols = 10, size_t parity_symbols = 4);
    std::vector<std::vector<uint8_t>> encode(const std::vector<std::vector<uint8_t>>& source_symbols) override;
    std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols, 
        size_t K_data_symbols,
        uint32_t block_id) override;
    const std::string& last_decode_status() const { return last_decode_status_; }
    long long last_encode_compute_us() const { return last_encode_compute_us_; }

private:
    using Encoder = RaptorQ__v1::Encoder<uint8_t*, uint8_t*>;
    size_t data_symbols_;
    size_t parity_symbols_;
    size_t last_K_ = 0;
    size_t last_symbol_size_ = 0;
    std::unique_ptr<Encoder> cached_encoder_;
    std::vector<uint8_t> persistent_buffer_;
    std::string last_decode_status_;
    long long last_encode_compute_us_ = -1;
};

} // namespace udpworm
