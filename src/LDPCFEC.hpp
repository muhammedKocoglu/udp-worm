#pragma once

#include "IFECStrategy.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace udpworm {

class LDPCFEC : public IFECStrategy {
public:
    LDPCFEC(size_t data_symbols = 10, size_t parity_symbols = 4);

    std::vector<std::vector<uint8_t>> encode(const std::vector<std::vector<uint8_t>>& source_symbols) override;
    std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
        size_t K_data_symbols,
        uint32_t block_id) override;

private:
    size_t data_symbols_;
    size_t parity_symbols_;
};

} // namespace udpworm
