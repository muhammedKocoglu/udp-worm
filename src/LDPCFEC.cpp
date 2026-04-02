#include "LDPCFEC.hpp"

extern "C" {
#include "of_openfec_api.h"
}

#include <cstdlib>
#include <cstring>
#include <iostream>

namespace udpworm {

LDPCFEC::LDPCFEC(size_t data_symbols, size_t parity_symbols)
    : data_symbols_(data_symbols),
      parity_symbols_(parity_symbols) {}

std::vector<std::vector<uint8_t>> LDPCFEC::encode(
    const std::vector<std::vector<uint8_t>>& source_symbols) {
    if (source_symbols.empty()) {
        std::cerr << "[ERROR] LDPC encode failed: no source symbols." << std::endl;
        return {};
    }

    const size_t K = source_symbols.size();
    if (data_symbols_ != 0 && K != data_symbols_) {
        std::cerr << "[ERROR] LDPC encode failed: K mismatch (expected "
                  << data_symbols_ << ", got " << K << ")." << std::endl;
        return {};
    }

    const size_t symbol_size = source_symbols[0].size();
    if (symbol_size == 0 || parity_symbols_ == 0) {
        std::cerr << "[ERROR] LDPC encode failed: invalid symbol size or parity count." << std::endl;
        return {};
    }

    for (const auto& symbol : source_symbols) {
        if (symbol.size() != symbol_size) {
            std::cerr << "[ERROR] LDPC encode failed: symbol size mismatch." << std::endl;
            return {};
        }
    }

    of_session_t* ses = nullptr;
    if (of_create_codec_instance(&ses, OF_CODEC_LDPC_STAIRCASE_STABLE, OF_ENCODER, 0) != OF_STATUS_OK) {
        std::cerr << "[ERROR] LDPC encode failed: codec instance creation failed." << std::endl;
        return {};
    }

    of_ldpc_parameters_t params;
    std::memset(&params, 0, sizeof(params));
    params.nb_source_symbols = static_cast<UINT32>(K);
    params.nb_repair_symbols = static_cast<UINT32>(parity_symbols_);
    params.encoding_symbol_length = static_cast<UINT32>(symbol_size);
    params.prng_seed = 0x1234;
    params.N1 = 3;

    if (of_set_fec_parameters(ses, reinterpret_cast<of_parameters_t*>(&params)) != OF_STATUS_OK) {
        std::cerr << "[ERROR] LDPC encode failed: setting FEC parameters failed." << std::endl;
        of_release_codec_instance(ses);
        return {};
    }

    const size_t N = K + parity_symbols_;
    std::vector<void*> enc_symbols_tab(N, nullptr);
    for (size_t i = 0; i < K; ++i) {
        enc_symbols_tab[i] = const_cast<uint8_t*>(source_symbols[i].data());
    }

    std::vector<std::vector<uint8_t>> parity_symbols;
    parity_symbols.resize(parity_symbols_, std::vector<uint8_t>(symbol_size));
    for (size_t i = 0; i < parity_symbols_; ++i) {
        enc_symbols_tab[K + i] = parity_symbols[i].data();
    }

    for (UINT32 esi = static_cast<UINT32>(K); esi < static_cast<UINT32>(N); ++esi) {
        if (of_build_repair_symbol(ses, enc_symbols_tab.data(), esi) != OF_STATUS_OK) {
            std::cerr << "[ERROR] LDPC encode failed for ESI " << esi << std::endl;
            of_release_codec_instance(ses);
            return {};
        }
    }

    of_release_codec_instance(ses);
    return parity_symbols;
}

std::vector<std::vector<uint8_t>> LDPCFEC::decode(
    const std::map<uint16_t, std::vector<uint8_t>>& received_symbols,
    size_t K_data_symbols,
    uint32_t block_id) {
    (void)block_id;
    if (received_symbols.empty() || K_data_symbols == 0) {
        return {};
    }
    if (data_symbols_ != 0 && K_data_symbols != data_symbols_) {
        return {};
    }

    const size_t symbol_size = received_symbols.begin()->second.size();
    if (symbol_size == 0) {
        return {};
    }

    for (const auto& pair : received_symbols) {
        if (pair.second.size() != symbol_size) {
            return {};
        }
    }

    of_session_t* ses = nullptr;
    if (of_create_codec_instance(&ses, OF_CODEC_LDPC_STAIRCASE_STABLE, OF_DECODER, 0) != OF_STATUS_OK) {
        return {};
    }

    of_ldpc_parameters_t params;
    std::memset(&params, 0, sizeof(params));
    params.nb_source_symbols = static_cast<UINT32>(K_data_symbols);
    params.nb_repair_symbols = static_cast<UINT32>(parity_symbols_);
    params.encoding_symbol_length = static_cast<UINT32>(symbol_size);
    params.prng_seed = 0x1234;
    params.N1 = 3;

    if (of_set_fec_parameters(ses, reinterpret_cast<of_parameters_t*>(&params)) != OF_STATUS_OK) {
        of_release_codec_instance(ses);
        return {};
    }

    for (const auto& pair : received_symbols) {
        const UINT32 esi = static_cast<UINT32>(pair.first);
        if (of_decode_with_new_symbol(ses, const_cast<uint8_t*>(pair.second.data()), esi) == OF_STATUS_ERROR) {
            of_release_codec_instance(ses);
            return {};
        }
    }

    if (!of_is_decoding_complete(ses)) {
        const of_status_t ret = of_finish_decoding(ses);
        (void)ret;
    }

    if (!of_is_decoding_complete(ses)) {
        of_release_codec_instance(ses);
        return {};
    }

    std::vector<void*> src_symbols_tab(K_data_symbols, nullptr);
    if (of_get_source_symbols_tab(ses, src_symbols_tab.data()) != OF_STATUS_OK) {
        of_release_codec_instance(ses);
        return {};
    }

    std::vector<std::vector<uint8_t>> decoded;
    decoded.reserve(K_data_symbols);
    for (size_t i = 0; i < K_data_symbols; ++i) {
        if (!src_symbols_tab[i]) {
            of_release_codec_instance(ses);
            return {};
        }
        decoded.emplace_back(static_cast<uint8_t*>(src_symbols_tab[i]),
                             static_cast<uint8_t*>(src_symbols_tab[i]) + symbol_size);
        if (received_symbols.find(static_cast<uint16_t>(i)) == received_symbols.end()) {
            free(src_symbols_tab[i]);
        }
    }

    of_release_codec_instance(ses);
    return decoded;
}

} // namespace udpworm
