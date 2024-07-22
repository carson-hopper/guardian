#pragma once

#include "Guardian/Guardian.h"
#include "Network/Detection/Mitigation.h"

#include <unordered_map>

class SynFlood: public Mitigation {
public:
    SynFlood(): Mitigation(TCP) {}

    PacketAction OnUpdate(Packet& packet) override;

private:
    std::unordered_map<std::string, int> m_FloodMap;
    float m_LastCheckTime = 0.0f;
};