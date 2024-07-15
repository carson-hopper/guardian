#pragma once

#include "Guardian/Network/Packet/IpPacket.h"

class Detection {
public:
    Detection(short protocol);
    virtual ~Detection() = default;

    virtual bool OnAttach() { return true; }
    virtual bool OnDetach() { return true; }
    virtual bool OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) { return true; }

    [[nodiscard]] const short &GetProtocol() const { return m_Protocol; }

protected:
    short m_Protocol = 0;
};