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

private:
    size_t data_symbols_;
    size_t parity_symbols_;
    std::string last_decode_status_;
};

} // namespace udpworm
