#pragma once

#include "Guardian/Core/PlatformDetection.h"

#include <memory>

#ifdef GD_DEBUG
	#if defined(GD_PLATFORM_WINDOWS)
		#define GD_DEBUGBREAK() __debugbreak()
	#elif defined(GD_PLATFORM_LINUX)
		#include <signal.h>
		#define GD_DEBUGBREAK() raise(SIGTRAP)
	#else
		#error "Platform doesn't support debugbreak yet!"
	#endif
	#define GD_ENABLE_ASSERTS
#else
	#define GD_DEBUGBREAK()
#endif

#define GD_EXPAND_MACRO(x) x
#define GD_STRINGIFY_MACRO(x) #x

#define BIT(x) (1 << x)

#define GD_BIND_EVENT_FN(fn) [this](auto&&... args) -> decltype(auto) { return this->fn(std::forward<decltype(args)>(args)...); }

namespace Guardian {

	template<typename T>
	using Scope = std::unique_ptr<T>;
	template<typename T, typename ... Args>
	constexpr Scope<T> CreateScope(Args&& ... args) {
		return std::make_unique<T>(std::forward<Args>(args)...);
	}

	template<typename T>
	using Ref = std::shared_ptr<T>;
	template<typename T, typename ... Args>
	constexpr Ref<T> CreateRef(Args&& ... args) {
		return std::make_shared<T>(std::forward<Args>(args)...);
	}

}

#include "Guardian/Core/Log.h"
#include "Guardian/Core/Assert.h"