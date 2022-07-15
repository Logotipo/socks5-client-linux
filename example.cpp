#include <iostream>
#include <unistd.h>
#include "proxymanager/proxymanager.h"

#define PROXY_IP        "127.0.0.1"
#define PROXY_PORT      1080
#define UDP_DST_IP      "28.28.28.28"
#define UDP_DST_PORT    2727
#define RCV_TRY_MAX     10
#define TCP_DST_IP      "27.27.27.27"
#define TCP_DST_PORT    2828

int main (int argc, char **argv)
{
    ProxyManager *proxyManagerUDP = new ProxyManager();
    ProxyManager *proxyManagerTCP = new ProxyManager();
    std::cout << "Socks5 client was started!" << std::endl;

    if (proxyManagerUDP->connectToProxy(PROXY_IP, PROXY_PORT, "", "", Socks5::PROXY_MODE::UDP_ASSOCIATE))
    {
        const char testPacket[] = "TEST_PACKET\0";
        char *testAnswer = new char[572]; // standart MTU
        int32_t sentResult = proxyManagerUDP->send(const_cast<char *>(&testPacket[0]), sizeof(testPacket), UDP_DST_IP, UDP_DST_PORT);
        if (sentResult > 0)
        {
            std::cout << "UDP packet was successful sent" << std::endl;
        }

        uint32_t tryCount = 0;
        int32_t messageLength = 0;
        while ((messageLength = proxyManagerUDP->read(testAnswer, 572)) < 1)// don`t get src addr
                                                                            // if this need: read(testAnswer, 572, &binAddr, &port)
        {
            tryCount++;
            if (tryCount >= RCV_TRY_MAX)
            {
                std::cout << "Don`t get answer..." << std::endl;
                break;
            }
            usleep(100 * 1000); // 10ms
        }
        // do something with answer
        delete[] testAnswer;
    }
    else
    {
        std::cout << "Proxy connection error: " << ProxyManager::getErrorString(proxyManagerUDP->lastErrorCode()) << std::endl;
    }

    if (proxyManagerTCP->connectToProxy(PROXY_IP, PROXY_PORT, "", "", Socks5::PROXY_MODE::CONNECTION, TCP_DST_IP, TCP_DST_PORT))
    {
        const char testPacket[] = "TEST_PACKET\0";
        char *testAnswer = new char[572]; // standart MTU
        int32_t sentResult = proxyManagerTCP->send(const_cast<char *>(&testPacket[0]), sizeof(testPacket));
        if (sentResult > 0)
        {
            std::cout << "TCP packet was successful sent" << std::endl;
        }
        if (proxyManagerTCP->read(testAnswer, 572) > 0) // blocking socket
        {
            //do something with answer
        }
        delete[] testAnswer;
    }
    else
    {
        std::cout << "Proxy connection error: " << ProxyManager::getErrorString(proxyManagerTCP->lastErrorCode()) << std::endl;
    }
    return 0;
}