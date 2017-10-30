#ifndef PACKETCLASS_H
#define PACKETCLASS_H
#pragma once

#endif // PACKETCLASS_H

#include <QVector>

class Packet;

bool srav(Packet &obj1,Packet &obj2);

class Packet
{
public:
    QVector <struct pcap_pkthdr *> mHeaders;
    QVector <uchar *> mDatas;
    QVector <const struct sniff_ethernet *> mEthernet;
    QVector <const struct sniff_ip *> mIp;
    QVector <const struct sniff_tcp *> mTcp;
    QVector <const u_char *> mPayload;
    QVector <int> mIndexes;

//    static int choose;

//    Packet();
//    Packet(const Packet &obj); //конструктор копирования
//    Packet operator = (Packet &obj); //присваивание

//    friend bool operator < (Packet &obj1,Packet &obj2);
//    friend bool operator < (const Packet &obj1,Packet &obj2);
//    friend bool operator < (Packet &obj1,const Packet &obj2);

};

//int Packet::choose=5;

//Packet::Packet()
//{}

//Packet::Packet(const Packet &obj)
//{
//    mHeaders[0] = obj.mHeaders[0];
//    mDatas[0] = obj.mDatas[0];
//    mEthernet[0] = obj.mEthernet[0];
//    mIp[0] = obj.mIp[0];
//    mTcp[0] = obj.mTcp[0];
//    mPayload[0] = obj.mPayload[0];
//    mIndexes[0] = obj.mIndexes[0];
//}
