#include "packetclass.h"

bool Packet::operator > (Packet &obj)
{
    if (mIp > obj.mIp) return true;
    return false;
}
