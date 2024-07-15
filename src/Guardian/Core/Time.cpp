#include "gdpch.h"
#include "Guardian/Core/Time.h"

#include <chrono>

namespace Guardian {

    float Time::GetTime() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::duration<float>>(duration).count();
    }
    
}