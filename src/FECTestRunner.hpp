#pragma once

#include "IFECStrategy.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace udpworm {

class FECTestRunner {
public:
    bool run_test(const std::string& fec_name,
                  const std::vector<std::pair<size_t, size_t>>& configs,
                  size_t symbol_size);
};

} // namespace udpworm
