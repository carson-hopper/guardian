#pragma once

#include "Guardian/Core/Base.h"
#include "Guardian/Core/Application.h"

#ifdef GD_PLATFORM_LINUX

extern Guardian::Application* Guardian::CreateApplication(ApplicationCommandLineArgs args);

int main(int argc, char **argv) {
    Log::Init();

    GD_PROFILE_BEGIN_SESSION("Startup", "GuardianProfile-Startup.json");
    auto application = Guardian::CreateApplication({ argc, argv });
	GD_PROFILE_END_SESSION();

    GD_PROFILE_BEGIN_SESSION("Runtime", "GuardianProfile-Runtime.json");
    if (application != nullptr) {
        application->Run();
    }
    GD_PROFILE_END_SESSION();

    GD_PROFILE_BEGIN_SESSION("Shutdown", "GuardianProfile-Shutdown.json");
    delete application;
	GD_PROFILE_END_SESSION();
}

#endif
