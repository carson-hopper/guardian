#include "gdpch.h"
#include "Network/Detection/TCP/ConnectionTracking.h"

#include "Guardian/Network/Packet/TcpPacket.h"

bool ConnectionTracking::OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) {
    GD_PROFILE_SCOPE("ConnectionTracking");

    if (const auto tcpPacket = std::make_shared<TcpPacket>(ipPacket)) {
        tcpPacket->SetConnectionState();
    }
    return true;
}