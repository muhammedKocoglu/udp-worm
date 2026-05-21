#include "ReedSolomonFEC.hpp"
#include <schifra/schifra_reed_solomon_encoder.hpp>
#include <schifra/schifra_reed_solomon_decoder.hpp>
#include <schifra/schifra_galois_field.hpp>
#include <schifra/schifra_sequential_root_generator_polynomial_creator.hpp>
#include <schifra/schifra_reed_solomon_block.hpp>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace udpworm {

namespace {
    constexpr std::size_t kFieldDescriptor = 8;
    // Matches Schifra examples; any consistent index works for encode/decode.
    constexpr std::size_t kGenPolyIndex = 120;
    // Field size for GF(2^8) is 2^8 - 1 = 255.
    constexpr std::size_t kNaturalLength = (1u << kFieldDescriptor) - 1;

}

struct ReedSolomonFEC::SchifraImplBase {
    virtual ~SchifraImplBase() = default;
    virtual std::vector<std::vector<uint8_t>> encode(
        const std::vector<std::vector<uint8_t>>& source_symbols) = 0;
    virtual std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
        size_t K_data_symbols,
        uint16_t block_id) = 0;
    virtual size_t data_symbols() const = 0;
    virtual size_t parity_symbols() const = 0;
};

template <size_t DataSymbols, size_t ParitySymbols>
struct ReedSolomonFEC::SchifraImpl final : ReedSolomonFEC::SchifraImplBase {
    static constexpr std::size_t kDataSymbols = DataSymbols;
    static constexpr std::size_t kParitySymbols = ParitySymbols;
    static constexpr std::size_t kCodeLength = kDataSymbols + kParitySymbols;
    static constexpr std::size_t kPaddingLength = kNaturalLength - kDataSymbols - kParitySymbols;

    schifra::galois::field field;
    schifra::galois::field_polynomial generator_polynomial;
    using Encoder = schifra::reed_solomon::shortened_encoder<
        kCodeLength, kParitySymbols, kDataSymbols, kNaturalLength, kPaddingLength>;
    using Decoder = schifra::reed_solomon::shortened_decoder<
        kCodeLength, kParitySymbols, kDataSymbols, kNaturalLength, kPaddingLength>;
    std::unique_ptr<Encoder> encoder;
    std::unique_ptr<Decoder> decoder;

    SchifraImpl() :
        field(kFieldDescriptor, schifra::galois::primitive_polynomial_size06, schifra::galois::primitive_polynomial06),
        generator_polynomial(field) {
        if (!schifra::make_sequential_root_generator_polynomial(field, kGenPolyIndex, kParitySymbols, generator_polynomial)) {
            std::cerr << "[FEC] Failed to create generator polynomial with kGenPolyIndex=" << kGenPolyIndex
                      << ", kParitySymbols=" << kParitySymbols << std::endl;
            throw std::runtime_error("Failed to create generator polynomial");
        }
        encoder = std::make_unique<Encoder>(field, generator_polynomial);
        decoder = std::make_unique<Decoder>(field, kGenPolyIndex);
    }

    std::vector<std::vector<uint8_t>> encode(
        const std::vector<std::vector<uint8_t>>& source_symbols) override {
        if (source_symbols.size() != kDataSymbols) {
            std::cerr << "[FEC] Encode expects K=" << kDataSymbols
                      << " but received " << source_symbols.size() << " symbols." << std::endl;
            return {};
        }

        if (source_symbols.empty()) {
            return {};
        }

        const std::size_t packet_size = source_symbols[0].size();

        std::vector<std::vector<uint8_t>> repair_symbols(kParitySymbols, std::vector<uint8_t>(packet_size));

        // Interleave: process column by column
        for (size_t i = 0; i < packet_size; ++i) {
            schifra::reed_solomon::block<kCodeLength, kParitySymbols> block;
            block.clear(); // Explicitly clear the block

            // Copy one byte from each packet into the block
            for (size_t j = 0; j < kDataSymbols; ++j) {
                block.data[j] = source_symbols[j][i];
            }
            // Explicitly zero-fill the remaining data positions in the block
            // (This is effectively the padding for the shortened code within the block)
            for (size_t j = kDataSymbols; j < kCodeLength; ++j) {
                block.data[j] = 0;
            }

            if (!encoder->encode(block)) {
                std::cerr << "[FEC] Encode failed for column " << i << std::endl;
                return {};
            }

            // Copy parity symbols to our repair_symbols structure
            for (size_t j = 0; j < kParitySymbols; ++j) {
                repair_symbols[j][i] = block.fec(j);
            }
        }

        return repair_symbols;
    }

    std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
        size_t K_data_symbols,
        uint16_t block_id) override {

        if (K_data_symbols != kDataSymbols) {
            return {};
        }

        if (received_symbols.size() < kDataSymbols) {
            return {};
        }

        const std::size_t packet_size = received_symbols.begin()->second.size();
        bool all_data_present = true;
        for (size_t i = 0; i < kDataSymbols; ++i) {
            if (received_symbols.find(static_cast<uint16_t>(i)) == received_symbols.end()) {
                all_data_present = false;
                break;
            }
        }
        if (all_data_present) {
            std::vector<std::vector<uint8_t>> direct_data(kDataSymbols);
            for (size_t i = 0; i < kDataSymbols; ++i) {
                direct_data[i] = received_symbols.at(static_cast<uint16_t>(i));
            }
            return direct_data;
        }
        std::vector<std::vector<uint8_t>> reconstructed_data(kDataSymbols, std::vector<uint8_t>(packet_size));

        // Interleave: process column by column
        for (size_t i = 0; i < packet_size; ++i) {
            schifra::reed_solomon::block<kCodeLength, kParitySymbols> block;
            block.clear(); // Initialize block data to zeros

            schifra::reed_solomon::erasure_locations_t erasure_locations;

            // Populate block data and identify erasures for this column
            for (size_t j = 0; j < kCodeLength; ++j) {
                const auto symbol_id = static_cast<uint16_t>(j);
                if (received_symbols.count(symbol_id)) {
                    block.data[j] = received_symbols.at(symbol_id)[i];
                } else {
                    erasure_locations.push_back(j);
                }
            }

            // If there are erasures, decode with erasure information
            if (!erasure_locations.empty()) {
                if (!decoder->decode(block, erasure_locations)) {
                    return {};
                }
            } else { // No erasures, just check for errors
                if (!decoder->decode(block)) {
                    return {};
                }
            }

            // Copy reconstructed data from the block
            for (size_t j = 0; j < kDataSymbols; ++j) {
                reconstructed_data[j][i] = block.data[j];
            }
        }

        return reconstructed_data;
    }

    size_t data_symbols() const override { return kDataSymbols; }
    size_t parity_symbols() const override { return kParitySymbols; }
};

template <size_t ParitySymbols>
struct ReedSolomonFEC::SchifraDynamicImpl final : ReedSolomonFEC::SchifraImplBase {
    static constexpr std::size_t kParitySymbols = ParitySymbols;
    static constexpr std::size_t kCodeLength = kNaturalLength;
    static constexpr std::size_t kDataSymbolsMax = kCodeLength - kParitySymbols;

    schifra::galois::field field;
    schifra::galois::field_polynomial generator_polynomial;
    using Encoder = schifra::reed_solomon::encoder<kCodeLength, kParitySymbols>;
    using Decoder = schifra::reed_solomon::decoder<kCodeLength, kParitySymbols>;
    std::unique_ptr<Encoder> encoder;
    std::unique_ptr<Decoder> decoder;

    SchifraDynamicImpl()
        : field(kFieldDescriptor,
                schifra::galois::primitive_polynomial_size06,
                schifra::galois::primitive_polynomial06),
          generator_polynomial(field) {
        if (!schifra::make_sequential_root_generator_polynomial(
                field, kGenPolyIndex, kParitySymbols, generator_polynomial)) {
            throw std::runtime_error("Failed to create generator polynomial");
        }
        encoder = std::make_unique<Encoder>(field, generator_polynomial);
        decoder = std::make_unique<Decoder>(field, kGenPolyIndex);
    }

    std::vector<std::vector<uint8_t>> encode(
        const std::vector<std::vector<uint8_t>>& source_symbols) override {
        if (source_symbols.empty()) {
            return {};
        }
        const std::size_t runtime_k = source_symbols.size();
        if (runtime_k > kDataSymbolsMax) {
            std::cerr << "[FEC] Reed-Solomon encode failed: K=" << runtime_k
                      << " exceeds max " << kDataSymbolsMax << " for M=" << kParitySymbols
                      << " (K+M must be <= 255)." << std::endl;
            return {};
        }

        const std::size_t packet_size = source_symbols[0].size();
        for (const auto& symbol : source_symbols) {
            if (symbol.size() != packet_size) {
                return {};
            }
        }

        std::vector<std::vector<uint8_t>> repair_symbols(
            kParitySymbols, std::vector<uint8_t>(packet_size, 0));

        for (size_t i = 0; i < packet_size; ++i) {
            schifra::reed_solomon::block<kCodeLength, kParitySymbols> block;
            block.clear();

            for (size_t j = 0; j < kDataSymbolsMax; ++j) {
                if (j < runtime_k) {
                    block.data[j] = source_symbols[j][i];
                } else {
                    block.data[j] = 0;
                }
            }

            if (!encoder->encode(block)) {
                std::cerr << "[FEC] Reed-Solomon encode failed for column " << i << std::endl;
                return {};
            }

            for (size_t p = 0; p < kParitySymbols; ++p) {
                repair_symbols[p][i] = block.fec(p);
            }
        }

        return repair_symbols;
    }

    std::vector<std::vector<uint8_t>> decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
        size_t K_data_symbols,
        uint16_t /*block_id*/) override {
        if (K_data_symbols == 0 || K_data_symbols > kDataSymbolsMax) {
            return {};
        }
        if (received_symbols.size() < K_data_symbols) {
            return {};
        }
        if (received_symbols.begin()->second.empty()) {
            return {};
        }

        const std::size_t packet_size = received_symbols.begin()->second.size();
        for (const auto& pair : received_symbols) {
            if (pair.second.size() != packet_size) {
                return {};
            }
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

        std::vector<std::vector<uint8_t>> reconstructed_data(
            K_data_symbols, std::vector<uint8_t>(packet_size, 0));

        for (size_t i = 0; i < packet_size; ++i) {
            schifra::reed_solomon::block<kCodeLength, kParitySymbols> block;
            block.clear();
            schifra::reed_solomon::erasure_locations_t erasure_locations;

            for (size_t j = 0; j < kDataSymbolsMax; ++j) {
                if (j < K_data_symbols) {
                    const uint16_t wire_id = static_cast<uint16_t>(j);
                    auto it = received_symbols.find(wire_id);
                    if (it != received_symbols.end()) {
                        block.data[j] = it->second[i];
                    } else {
                        erasure_locations.push_back(j);
                    }
                } else {
                    block.data[j] = 0;
                }
            }

            for (size_t p = 0; p < kParitySymbols; ++p) {
                const uint16_t wire_id = static_cast<uint16_t>(K_data_symbols + p);
                const size_t code_index = kDataSymbolsMax + p;
                auto it = received_symbols.find(wire_id);
                if (it != received_symbols.end()) {
                    block.data[code_index] = it->second[i];
                } else {
                    erasure_locations.push_back(code_index);
                }
            }

            const bool ok = erasure_locations.empty()
                                ? decoder->decode(block)
                                : decoder->decode(block, erasure_locations);
            if (!ok) {
                return {};
            }

            for (size_t j = 0; j < K_data_symbols; ++j) {
                reconstructed_data[j][i] = block.data[j];
            }
        }

        return reconstructed_data;
    }

    size_t data_symbols() const override { return kDataSymbolsMax; }
    size_t parity_symbols() const override { return kParitySymbols; }
};

ReedSolomonFEC::ReedSolomonFEC(size_t data_symbols, size_t parity_symbols) {
    if (data_symbols == 0 || parity_symbols == 0) {
        throw std::invalid_argument("Reed-Solomon requires K>0 and M>0.");
    }
    if (data_symbols + parity_symbols > kNaturalLength) {
        std::ostringstream oss;
        oss << "Invalid Reed-Solomon configuration K=" << data_symbols
            << " M=" << parity_symbols << " (K+M must be <= " << kNaturalLength << ")";
        throw std::invalid_argument(oss.str());
    }
    if (parity_symbols > 128) {
        std::ostringstream oss;
        oss << "Unsupported Reed-Solomon parity M=" << parity_symbols
            << " (supported range is 1..128).";
        throw std::invalid_argument(oss.str());
    }

    auto make_impl_for_m = [&]<size_t M>(auto&& self, size_t target)
        -> std::unique_ptr<SchifraImplBase> {
        if constexpr (M > 128) {
            return nullptr;
        } else {
            if (target == M) {
                return std::make_unique<SchifraDynamicImpl<M>>();
            }
            return self.template operator()<M + 1>(self, target);
        }
    };

    impl_ = make_impl_for_m.template operator()<1>(make_impl_for_m, parity_symbols);
    if (!impl_) {
        std::ostringstream oss;
        oss << "Unsupported Reed-Solomon parity M=" << parity_symbols;
        throw std::invalid_argument(oss.str());
    }
}

ReedSolomonFEC::~ReedSolomonFEC() = default;

std::vector<std::vector<uint8_t>> ReedSolomonFEC::encode(const std::vector<std::vector<uint8_t>>& source_symbols) {
    if (source_symbols.empty()) {
        std::cerr << "[ERROR] Reed-Solomon encode failed: no source symbols." << std::endl;
        return {};
    }
    auto parity = impl_->encode(source_symbols);
    if (parity.empty()) {
        std::cerr << "[ERROR] Reed-Solomon encode failed for K=" << source_symbols.size() << std::endl;
    }
    return parity;
}

std::vector<std::vector<uint8_t>> ReedSolomonFEC::decode(
        const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
        size_t K_data_symbols,
        uint16_t block_id) {
    return impl_->decode(received_symbols, K_data_symbols, block_id);
}

} // namespace udpworm
