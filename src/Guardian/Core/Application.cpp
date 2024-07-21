#include "gdpch.h"
#include "Guardian/Core/Application.h"
#include "Guardian/Core/Time.h"

#include <utility>

namespace Guardian {

    Application* Application::s_Instance = nullptr;

    Application::Application(ApplicationSpecification  specification)
		: m_Specification(std::move(specification)) {
        GD_PROFILE_FUNCTION();

        GD_CORE_ASSERT(!s_Instance, "Application already exists!");
        s_Instance = this;

        GD_CORE_INFO("Application created!");
    }

    Application::~Application() {
        GD_PROFILE_FUNCTION();
    }

    void Application::Close() {
        GD_PROFILE_FUNCTION();

        m_Running = false;
        for (const auto& layer : m_LayerStack)
            layer->OnDetach();
    }

    void Application::Run() {
        GD_PROFILE_FUNCTION();

        while (m_Running) {
            GD_PROFILE_SCOPE("RunLoop");

            const float time = Time::GetTime();
            const Timestep timestep = time - m_LastFrameTime;

        	for (const auto& layer : m_LayerStack)
        		layer->OnUpdate(timestep);

            m_LastFrameTime = time;
        }
    }
}