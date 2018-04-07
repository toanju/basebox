#pragma once

#include <cstddef>

namespace basebox {

struct packet {
  std::size_t len; ///< actual lenght written into data
  char data[0];    ///< total allocated buffer
};
} // namespace basebox
