#pragma once

#include "Guardian/Core/Base.h"

#include <linux/netfilter.h>

enum PacketAction: uint32_t {
    DROP = NF_DROP,
    ACCEPT = NF_ACCEPT,
    STOLEN = NF_STOLEN,
    QUEUE = NF_QUEUE,
    REPEAT = NF_REPEAT
};