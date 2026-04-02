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
        uint32_t block_id) = 0;
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
        uint32_t block_id) override {

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

ReedSolomonFEC::ReedSolomonFEC(size_t data_symbols, size_t parity_symbols) {
    if (data_symbols == 10 && parity_symbols == 4) {
        impl_ = std::make_unique<SchifraImpl<10, 4>>();
    } else if (data_symbols == 50 && parity_symbols == 10) {
        impl_ = std::make_unique<SchifraImpl<50, 10>>();
    } else if (data_symbols == 100 && parity_symbols == 20) {
        impl_ = std::make_unique<SchifraImpl<100, 20>>();
    } else {
        std::ostringstream oss;
        oss << "Unsupported Reed-Solomon configuration K=" << data_symbols
            << " M=" << parity_symbols;
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
        uint32_t block_id) {
    return impl_->decode(received_symbols, K_data_symbols, block_id);
}

} // namespace udpworm
