#include "gdpch.h"
#include "Guardian/Network/TcpConnection.h"

TcpConnection::TcpConnection()
    : m_State(UNKNOWN), m_StateLast(UNKNOWN), m_LastUpdated(0) {
}

void TcpConnection::SetState(uint8_t flags) {
    m_StateLast = m_State;

    switch (m_State) {
        case UNKNOWN:
        case CLOSED:
            if (flags & 0x02) { // SYN
                m_State = SYN_SENT;
            }
            break;
        case SYN_SENT:
            if ((flags & 0x12) == 0x12) { // SYN + ACK
                m_State = SYN_RECEIVED;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case SYN_RECEIVED:
            if (flags & 0x10) { // ACK
                m_State = ESTABLISHED;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case ESTABLISHED:
            if (flags & 0x01) { // FIN
                m_State = FIN_WAIT_1;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case FIN_WAIT_1:
            if ((flags & 0x10) && !(flags & 0x01)) { // ACK, not FIN
                m_State = FIN_WAIT_2;
            } else if ((flags & 0x11) == 0x11) { // FIN + ACK
                m_State = TIME_WAIT;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case FIN_WAIT_2:
            if (flags & 0x01) { // FIN
                m_State = TIME_WAIT;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case CLOSE_WAIT:
            if (flags & 0x01) { // FIN
                m_State = LAST_ACK;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case CLOSING:
            if (flags & 0x10) { // ACK
                m_State = TIME_WAIT;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case LAST_ACK:
            if (flags & 0x10) { // ACK
                m_State = CLOSED;
            } else if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        case TIME_WAIT:
            if (flags & 0x04) { // RST
                m_State = RESET;
            }
            break;
        default:
            m_State = UNKNOWN;
            break;
    }

    m_LastUpdated = Time::GetTime();
}
