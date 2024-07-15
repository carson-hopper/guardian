#pragma once

#include "Guardian/Core/Base.h"

#include "Guardian/Core/Layer.h"
#include "Guardian/Core/Timestep.h"

#include <vector>

int main(int argc, char **argv);

namespace Guardian {

    struct ApplicationCommandLineArgs {
		int Count = 0;
		char** Args = nullptr;

		const char* operator[](int index) const {
			return Args[index];
		}
	};

    struct ApplicationSpecification {
		std::string WorkingDirectory;
		ApplicationCommandLineArgs CommandLineArgs;
	};

    
    class Application {
    public:

        Application(ApplicationSpecification  specification);
        virtual ~Application();

    	template<typename T>
		bool PushLayer() {
			static_assert(std::is_base_of<Layer, T>::value, "Pushed type is not subclass of Layer!");

    		const auto layer = std::make_shared<T>();
			m_LayerStack.emplace_back(layer);
			return layer->OnAttach();
		}

		bool PushLayer(const std::shared_ptr<Layer>& layer) {
    		m_LayerStack.emplace_back(layer);
    		return layer->OnAttach();
    	}

        void Close();

        static Application &Get() { return *s_Instance; }
    	bool &IsRunning() { return m_Running; }

    	[[nodiscard]] const ApplicationSpecification& GetSpecification() const { return m_Specification; }

    private:
        void Run();

    private:
    	ApplicationSpecification m_Specification;
		std::vector<std::shared_ptr<Layer>> m_LayerStack;
        bool m_Running = true;
        float m_LastFrameTime = 0.0f;

    private:
        static Application *s_Instance;
        friend int ::main(int argc, char **argv);
    };

    // To be defined in CLIENT
    Application *CreateApplication(ApplicationCommandLineArgs args);
}