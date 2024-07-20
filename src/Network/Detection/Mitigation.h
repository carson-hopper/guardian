#pragma once

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/Packet.h"
#include "Guardian/Network/Packet/PacketAction.h"
#include "Guardian/Network/Protocol.h"

class Mitigation {
public:
    explicit Mitigation(const Protocol protocol): m_Protocol(protocol) {}

    [[nodiscard]] virtual Protocol GetProtocol() const { return m_Protocol; }

    virtual bool OnAttach() { return true; }
    virtual bool OnDetach() { return true; }
    virtual std::tuple<PacketAction, Buffer&> OnUpdate(const Ref<Packet>& packet) {
        Buffer buffer = packet->GetBuffer();
        return {ACCEPT, buffer};
    }

private:
    Protocol m_Protocol;
};