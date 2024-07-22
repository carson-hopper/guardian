#pragma once

#include "Guardian/Guardian.h"
#include "Network/Detection/Mitigation.h"

class DnsBlock: public Mitigation {
public:
    DnsBlock(): Mitigation(UDP) {}

    bool OnAttach() override;
    PacketAction OnUpdate(Packet& packet) override;

private:
    std::tuple<std::string, std::vector<std::string>> ParseDnsRequest(Packet& packet);

public:
    static std::unordered_map<std::string, std::vector<std::string>> s_Domains;

private:
    std::vector<std::string> m_BlockedDomains;
    float m_LastCheckTime = 0.0f;
};