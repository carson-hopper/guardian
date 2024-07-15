#pragma once

#include "Guardian//Core/Base.h"
#include "Guardian/Core/Time.h"

enum TcpConnectionState: short {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    RESET,
    UNKNOWN
};

class TcpConnection {
public:
    TcpConnection();

    void SetState(uint8_t flags);
    [[nodiscard]] TcpConnectionState GetState() const { return m_State; }
    [[nodiscard]] TcpConnectionState GetStateLast() const { return m_StateLast; }

private:
    TcpConnectionState m_State;
    TcpConnectionState m_StateLast;
    float m_LastUpdated;

};