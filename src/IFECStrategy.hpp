#pragma once

#include <vector>
#include <cstdint>
#include <span>
#include <map>

namespace udpworm {

class IFECStrategy {
public:
    virtual ~IFECStrategy() = default;

    // Takes a block of K source symbols, returns a block of N-K repair symbols.
    virtual std::vector<std::vector<uint8_t>> encode(const std::vector<std::vector<uint8_t>>& source_symbols) = 0;
    
    // Takes a map of received symbols (data and parity) and reconstructs the original K data symbols.
    virtual std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols, 
        size_t K_data_symbols,
        uint32_t block_id) = 0;
};

} // namespace udpworm
