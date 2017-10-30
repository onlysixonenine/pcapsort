#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "packetclass.h"
#include <algorithm>

using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->pbStart,SIGNAL(clicked()),SLOT(slotCapture()));
    connect(ui->pbSort,SIGNAL(clicked()),SLOT(slotSort()));

    mSize_ethernet = sizeof(struct sniff_ethernet);
    mSize_ip = sizeof(struct sniff_ip);
    mSize_tcp = sizeof(struct sniff_tcp);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::slotCapture()
{
    mPacket.resize(n);

    mPacket.clear();
//    for (int i=0; i<n; i++)
//    {
//        mPacket[i].mHeaders.clear();
//        mPacket[i].mDatas.clear();
//    }

    ui->te->clear();

    char error[PCAP_ERRBUF_SIZE];
    QString file("E:/QtProject/pcapproject/pcap_sort/example.pcap");

    pcap_t *handle = pcap_open_offline(file.toStdString().c_str(), error);

    ui->te->append("Список пакетов:");

    for (int i=0; i<n; i++)
    {
        struct pcap_pkthdr *header;
        const u_char *data;

        pcap_next_ex(handle,&header,&data);

        mPacket[i].mHeaders.push_back(new pcap_pkthdr);
        *mPacket[i].mHeaders[0] =* header;
        mPacket[i].mDatas.push_back(new u_char[mPacket[i].mHeaders[0]->len]);
        for (unsigned j = 0; j < mPacket[i].mHeaders[0]->len; j++)
            mPacket[i].mDatas[0][j] = data[j];
        mPacket[i].mEthernet.push_back((struct sniff_ethernet*)(mPacket[i].mDatas[0]));

        mPacket[i].mIp.push_back((struct sniff_ip*)(mPacket[i].mDatas[0] + mSize_ethernet));
        mPacket[i].mTcp.push_back((struct sniff_tcp*)(mPacket[i].mDatas[0] + mSize_ethernet + mSize_ip));
        mPacket[i].mPayload.push_back((u_char *)(mPacket[i].mDatas[0] + mSize_ethernet + mSize_ip + mSize_tcp));
        mPacket[i].mIndexes.push_back(i+1);

        ui->te->append(QString("\n===== Пакет №%1 =====").arg(mPacket[i].mIndexes[0]));
        ui->te->append(QString("Длина пакета: %1").arg(header->caplen));
        ui->te->append(QString("Получено: %1").arg(header->len));
        ui->te->append(QString("Метка времени: %1").arg(header->ts.tv_sec));

    }

    pcap_close(handle);
}

void MainWindow::slotSort()
{
    ui->te->clear();
    if (ui->comboBox->currentText()=="IP")
    {
        if (ui->cb->currentText()=="По длине")
        {

//            for (int i=0; i < mPacket.size(); i++)
//                for (int j=0; j < mPacket.size()-1; j++)
//                    if(mPacket[i].mIp[0]->ip_len > mPacket[j].mIp[0]->ip_len) Exchange(i,j);

            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp->ip_len > mPacket[j+h].mIp->ip_len)
                            Exchange(j, j+h);
                        else j = 0;
        }

        for (int i=0; i<n; i++)
        {
            ui->te->append(QString("===== Пакет №%1 =====").arg(mPacket[i].mIndexes[0]));
            ui->te->append(QString("Длина пакета: %1").arg(mPacket[i].mHeaders[0]->caplen));
            ui->te->append(QString("Получено: %1").arg(mPacket[i].mHeaders[0]->len));
            ui->te->append(QString("Метка времени: %1").arg(mPacket[i].mHeaders[0]->ts.tv_sec));

            ui->te->append(QString("========= IP сортировка: ========="));
            ui->te->append(QString("Длина: %1").arg(mPacket[i].mIp[0]->ip_len));
            ui->te->append(QString("Время жизни: %1").arg(mPacket[i].mIp[0]->ip_ttl));
            ui->te->append(QString("Адрес получателя: %1").arg(mPacket[i].mIp[0]->ip_dst.s_addr));
            ui->te->append(QString("Адрес отправителя: %1").arg(mPacket[i].mIp[0]->ip_src.s_addr));
            ui->te->append(QString("Длина заголовочной части пакета: %1").arg(mPacket[i].mIp[0]->ip_vhl));
            ui->te->append(QString("Контрольная сумма: %1").arg(mPacket[i].mIp[0]->ip_sum));
            ui->te->append(QString("Протокола транспортного уровня: %1").arg(mPacket[i].mIp[0]->ip_p)); // 6 - TCP, 17 - UDP
            ui->te->append(QString("Тип обслуживания: %1").arg(mPacket[i].mIp[0]->ip_tos)); //0-2 приоритет данного IP-сегмент
            ui->te->append(QString("\n========================================\n"));
        }
    }
}

void MainWindow::Exchange(int i, int j)
{
    struct pcap_pkthdr *xHeaders           = mPacket[i].mHeaders[0];
    uchar *xDatas                          = mPacket[i].mDatas[0];
    const struct sniff_ethernet *xEthernet = mPacket[i].mEthernet[0];
    const struct sniff_ip *xIp             = mPacket[i].mIp[0];
    const struct sniff_tcp *xTcp           = mPacket[i].mTcp[0];
    const u_char *xPayload                 = mPacket[i].mPayload[0];
    int xIndexes                           = mPacket[i].mIndexes[0];

    mPacket[i].mHeaders[0] = mPacket[j].mHeaders[0];
    mPacket[i].mDatas[0] = mPacket[j].mDatas[0];
    mPacket[i].mEthernet[0] = mPacket[j].mEthernet[0];
    mPacket[i].mIp[0] = mPacket[j].mIp[0];
    mPacket[i].mTcp[0] = mPacket[j].mTcp[0];
    mPacket[i].mPayload[0] = mPacket[j].mPayload[0];
    mPacket[i].mIndexes[0] = mPacket[j].mIndexes[0];

    mPacket[j].mHeaders[0] = xHeaders;
    mPacket[j].mDatas[0] = xDatas;
    mPacket[j].mEthernet[0] = xEthernet;
    mPacket[j].mIp[0] = xIp;
    mPacket[j].mTcp[0] = xTcp;
    mPacket[j].mPayload[0] = xPayload;
    mPacket[j].mIndexes[0] = xIndexes;
}

//bool operator<(Packet &obj1,Packet &obj2)
//{
//    switch (Packet::choose)
//{
//    case 5:
//        if (obj1.mIp[0]->ip_len < obj2.mIp[0]->ip_len) return true;
//        else return false;
//        break;
//    }
//}

//bool operator<(const Packet &obj1,Packet &obj2)
//{
//    switch (Packet::choose)
//{
//    case 5:
//        if (obj1.mIp[0]->ip_len < obj2.mIp[0]->ip_len) return true;
//        else return false;
//        break;
//    }
//}
//bool operator<(Packet &obj1,const Packet &obj2)
//{
//    switch (Packet::choose)
//{
//    case 5:
//        if (obj1.mIp[0]->ip_len < obj2.mIp[0]->ip_len) return true;
//        else return false;
//        break;
//    }
//}
