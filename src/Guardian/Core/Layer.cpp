#include "gdpch.h"
#include "Guardian/Core/Layer.h"

#include <utility>

namespace Guardian {

    Layer::Layer(std::string name)
        : m_DebugName(std::move(name)) {

    }

}