#pragma once

#include "Guardian/Guardian.h"
#include "Network/Detection/Mitigation.h"

#include <unordered_map>

class IcmpFlood: public Mitigation {
public:
    IcmpFlood(): Mitigation(ICMP) {}

    std::tuple<PacketAction, Buffer&> OnUpdate(const Ref<Packet>& packet) override;

private:
    std::unordered_map<uint32_t, int> m_FloodMap;
    float m_LastCheckTime = 0.0f;
};