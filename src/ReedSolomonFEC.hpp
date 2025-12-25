#pragma once

#include "IFECStrategy.hpp"
#include <span>
#include <vector>
#include <cstdint>
#include <map>
#include <memory>

namespace udpworm {

class ReedSolomonFEC : public IFECStrategy {
public:
    ReedSolomonFEC(size_t data_symbols = 10, size_t parity_symbols = 4);
    ~ReedSolomonFEC();

    std::vector<std::vector<uint8_t>> encode(const std::vector<std::vector<uint8_t>>& source_symbols) override;
    std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols, 
        size_t K_data_symbols,
        uint32_t block_id) override;

private:
    struct SchifraImplBase;
    template <size_t DataSymbols, size_t ParitySymbols>
    struct SchifraImpl;
    std::unique_ptr<SchifraImplBase> impl_;
};

} // namespace udpworm
