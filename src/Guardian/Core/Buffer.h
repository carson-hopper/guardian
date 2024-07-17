#pragma once

#include <cstdint>
#include <cstring>

namespace Guardian {

    // Non-owning raw buffer class
    struct Buffer {
        uint8_t* Data = nullptr;
        uint64_t Size = 0;

        Buffer() = default;

        Buffer(const u_char* buffer, const uint64_t size) {
            Size = size;
            Data = (uint8_t*)buffer;
        }
        Buffer(const uint64_t size) {
            Allocate(size);
        }

        Buffer(const Buffer&) = default;

        static Buffer Copy(Buffer other) {
            const Buffer result(other.Size);
            memcpy(result.Data, other.Data, other.Size);
            return result;
        }

        void Allocate(const uint64_t size) {
            Release();

            Data = new uint8_t[size];
            Size = size;
        }

        void Release() {
            delete[] Data;
            Data = nullptr;
            Size = 0;
        }

        template<typename T>
        T* As() {
            return (T*)Data;
        }

    };
}