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

Guardian::Application *Guardian::CreateApplication(ApplicationCommandLineArgs args) {
    std::cerr << std::format("{} v{}", GD_APPLICATION, GD_APPLICATION_VERSION) << std::endl;
    std::cerr << std::endl;

#ifdef GD_PLATFORM_LINUX
    signal(SIGINT, signal_handler);
#endif

    Guardian::ApplicationSpecification spec;
    spec.CommandLineArgs = args;
    spec.WorkingDirectory = "./";

    application = new Guardian::Application(spec);
    if (!application->PushLayer<NfqLayer>())
        return nullptr;

    return application;
}