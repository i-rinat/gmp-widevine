#pragma once

#include <iostream>

#define DEBUG_TRACE

#ifdef DEBUG_TRACE
#define LOGF    std::cout << "gmp-widevine/F: "
#else
#define LOGF    while (0) std::cout
#endif // DEBUG_TRACE

#define LOGZ    std::cout << "gmp-widevine/Z: "
