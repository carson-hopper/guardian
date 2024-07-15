#pragma once

#include "Guardian/Network/Packet/IpPacket.h"
#include "Network/Detection/Detection.h"

class ConnectionTracking: public Detection {
public:

    ConnectionTracking(const short protocol): Detection(protocol) {}

    bool OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) override;

};