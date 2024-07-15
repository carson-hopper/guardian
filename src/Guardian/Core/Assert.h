#pragma once

#include "Guardian/Core/Base.h"
#include "Guardian/Core/Log.h"
#include <filesystem>

#ifdef GD_ENABLE_ASSERTS

    // Alteratively we could use the same "default" message for both "WITH_MSG" and "NO_MSG" and
    // provide support for custom formatting by concatenating the formatting string instead of having the format inside the default message
    #define GD_INTERNAL_ASSERT_IMPL(type, check, msg, ...) { if(!(check)) { GD##type##ERROR(msg, __VA_ARGS__); GD_DEBUGBREAK(); } }
    #define GD_INTERNAL_ASSERT_WITH_MSG(type, check, ...) GD_INTERNAL_ASSERT_IMPL(type, check, "Assertion failed: {0}", __VA_ARGS__)
    #define GD_INTERNAL_ASSERT_NO_MSG(type, check) GD_INTERNAL_ASSERT_IMPL(type, check, "Assertion '{0}' failed at {1}:{2}", GD_STRINGIFY_MACRO(check), std::filesystem::path(__FILE__).filename().string(), __LINE__)

    #define GD_INTERNAL_ASSERT_GET_MACRO_NAME(arg1, arg2, macro, ...) macro
    #define GD_INTERNAL_ASSERT_GET_MACRO(...) GD_EXPAND_MACRO( GD_INTERNAL_ASSERT_GET_MACRO_NAME(__VA_ARGS__, GD_INTERNAL_ASSERT_WITH_MSG, GD_INTERNAL_ASSERT_NO_MSG) )

    // Currently accepts at least the condition and one additional parameter (the message) being optional
    #define GD_ASSERT(...) GD_EXPAND_MACRO( GD_INTERNAL_ASSERT_GET_MACRO(__VA_ARGS__)(_, __VA_ARGS__) )
    #define GD_CORE_ASSERT(...) GD_EXPAND_MACRO( GD_INTERNAL_ASSERT_GET_MACRO(__VA_ARGS__)(_CORE_, __VA_ARGS__) )
#else
    #define GD_ASSERT(...)
    #define GD_CORE_ASSERT(...)
#endif