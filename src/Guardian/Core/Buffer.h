#pragma once

#include <cstdint>
#include <cstring>

namespace Guardian {

    // Non-owning raw buffer class
    struct Buffer {
        uint8_t* Data = nullptr;
        uint64_t Size = 0;

        Buffer() = default;

        Buffer(uint8_t* buffer, const uint64_t size) {
            Size = size;
            Data = buffer;
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

        void ReAllocate(const uint64_t size) {
            auto* data = new uint8_t[size];
            memcpy(data, Data, Size);

            Allocate(size);

            memcpy(Data, data, Size);
            delete[] data;
        }

        void Allocate(const uint64_t size) {
            Release();

            Data = new uint8_t[size];
            Size = size;
        }

        void Release() {
            if (Data == nullptr && Size <= 0)
                return;

            delete[] Data;
            Data = nullptr;
            Size = 0;
        }

        template<typename T>
        T* As() {
            return (T*)Data;
        }

        void PutInt(const uint32_t position, const uint32_t data) {
            if ((position + sizeof(uint32_t)) > Size)
                ReAllocate(position + sizeof(uint32_t));

            memcpy(Data, &data, sizeof(uint32_t));
        }

        void PutShort(const uint32_t position, const uint16_t data) {
            if ((position + sizeof(uint16_t)) > Size)
                ReAllocate(position + sizeof(uint16_t));

            memcpy(Data, &data, sizeof(uint32_t));
        }

        void PutByte(const uint32_t position, const uint8_t data) {
            if ((position + sizeof(uint8_t)) > Size)
                ReAllocate(position + sizeof(uint8_t));

            memcpy(Data, &data, sizeof(uint32_t));
        }

        void Put(const uint32_t position, const uint8_t* data, const uint32_t length) {
            if ((position + length) > Size)
                ReAllocate(position + length);

            memcpy(Data, &data, length);
        }

    };
}