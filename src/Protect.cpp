#include "gdpch.h"

#include <chrono>
#include <mutex>
#include <ctime>
#include <cstring>
#include <fstream>
#include <csignal>

#ifndef __APPLE__
#include <hiredis/hiredis.h>
#endif

#include "Guardian/Guardian.h"
#include "Guardian/Core/EntryPoint.h"

#include "Layer/NfqLayer.h"

Guardian::Application* application = nullptr;

#ifdef GD_PLATFORM_LINUX
void signal_handler(int signum) {
    if (application != nullptr)
        application->Close();
}

#endif

Application *Guardian::CreateApplication(ApplicationCommandLineArgs args) {
    std::cerr << std::format("{} v{}", GD_APPLICATION, GD_APPLICATION_VERSION) << std::endl;
    std::cerr << std::endl;

#ifdef GD_PLATFORM_LINUX
    signal(SIGINT, signal_handler);
#endif

    ApplicationSpecification spec;
    spec.CommandLineArgs = args;
    spec.WorkingDirectory = "./";

    application = new Guardian::Application(spec);
    GD_ASSERT(application->PushLayer<NfqLayer>(), "Nfq failed")

    return application;
}