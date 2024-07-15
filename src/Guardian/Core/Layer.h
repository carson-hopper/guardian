#pragma once

#include "Guardian/Core/Base.h"
#include "Guardian/Core/Timestep.h"

namespace Guardian {

    class Layer {
    public:

        Layer(std::string = "Layer");
        virtual ~Layer() = default;

        virtual bool OnAttach() { return true; }
		virtual bool OnDetach() { return true; }
		virtual void OnUpdate(Timestep ts) {}

		[[nodiscard]] const std::string& GetName() const { return m_DebugName; }

	protected:
		std::string m_DebugName;

    };
}