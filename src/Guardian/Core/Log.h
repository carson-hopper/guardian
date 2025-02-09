#pragma once

#include "Guardian//Core/Base.h"

#define GLM_ENABLE_EXPERIMENTAL
#include "glm/gtx/string_cast.hpp"

#include <spdlog/spdlog.h>

namespace Guardian {

	class Log
	{
	public:
		static void Init();

		static Ref<spdlog::logger>& GetCoreLogger() { return s_CoreLogger; }
		static Ref<spdlog::logger>& GetClientLogger() { return s_ClientLogger; }
	private:
		static Ref<spdlog::logger> s_CoreLogger;
		static Ref<spdlog::logger> s_ClientLogger;
	};

}

template<typename OStream, glm::length_t L, typename T, glm::qualifier Q>
inline OStream& operator<<(OStream& os, const glm::vec<L, T, Q>& vector)
{
	return os << glm::to_string(vector);
}

template<typename OStream, glm::length_t C, glm::length_t R, typename T, glm::qualifier Q>
inline OStream& operator<<(OStream& os, const glm::mat<C, R, T, Q>& matrix)
{
	return os << glm::to_string(matrix);
}

template<typename OStream, typename T, glm::qualifier Q>
inline OStream& operator<<(OStream& os, glm::qua<T, Q> quaternion)
{
	return os << glm::to_string(quaternion);
}

// Core log macros
#define GD_CORE_TRACE(...)    ::Guardian::Log::GetCoreLogger()->trace(__VA_ARGS__)
#define GD_CORE_INFO(...)     ::Guardian::Log::GetCoreLogger()->info(__VA_ARGS__)
#define GD_CORE_WARN(...)     ::Guardian::Log::GetCoreLogger()->warn(__VA_ARGS__)
#define GD_CORE_ERROR(...)    ::Guardian::Log::GetCoreLogger()->error(__VA_ARGS__)
#define GD_CORE_CRITICAL(...) ::Guardian::Log::GetCoreLogger()->critical(__VA_ARGS__)

// Client log macros
#define GD_TRACE(...)         ::Guardian::Log::GetClientLogger()->trace(__VA_ARGS__)
#define GD_INFO(...)          ::Guardian::Log::GetClientLogger()->info(__VA_ARGS__)
#define GD_WARN(...)          ::Guardian::Log::GetClientLogger()->warn(__VA_ARGS__)
#define GD_ERROR(...)         ::Guardian::Log::GetClientLogger()->error(__VA_ARGS__)
#define GD_CRITICAL(...)      ::Guardian::Log::GetClientLogger()->critical(__VA_ARGS__)