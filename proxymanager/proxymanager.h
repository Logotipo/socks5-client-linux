/******************************************************************************
 * File: proxymanager.h
 * Description: Socks5-client for linux with supporting CONNECT and UDP_ASSOCIATE commands.
 * Created: 14.07.2022
 * Author: Logotipo
******************************************************************************/
#ifndef PROXYMANAGER_H
#define PROXYMANAGER_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string>

namespace Socks5
{
    enum class PROXY_MODE
    {
        CONNECTION = 1,
        BIND,
        UDP_ASSOCIATE
    };
    enum class PROXY_ERROR
    {
        SUCCESS = 0,
        CONNECTION,
        NETWORK,
        PROTOCOL,
        AUTH_METHOD,
        UDP_BIND,
        IMPOSSIBLE,
        MEMORY,
        DST_HOST,
        SIGNIN,
        //command answer errors
        GENERAL,
        RULESET,
        NETWORK_UNREACHEBLE,
        HOST_UNREACHEBLE,
        CONNECTION_REFUSED,
        TTL,
        COMMAND_NOT_SUPPORT,
        ADDRESS_TYPE,
        UNKNOW
    };
    enum class PROXY_WAIT_MODE
    {
        PROXY_WAIT_NONE = 0,
        PROXY_WAIT_SEND = 1,
        PROXY_WAIT_RECEIVE = 2
    };

#pragma pack(push, 1)
    struct AuthRequestHeader
    {
        uint8_t	byteVersion;
        uint8_t	byteAuthMethodsCount;
        uint8_t	byteMethods[1];
    };

    struct AuthRespondHeader
    {
        uint8_t	byteVersion;
        uint8_t	byteAuthMethod;
    };

    struct AuthUPRespondtHeader {
        uint8_t byteVersion;
        uint8_t byteRespondCode;
    };

    struct ConnectRequestHeader
    {
        uint8_t     byteVersion;
        uint8_t     byteCommand;
        uint8_t     byteReserved;
        uint8_t     byteAddressType;
        uint32_t	ulAddressIPv4;
        uint16_t	usPort;
    };

    struct ConnectRespondHeader
    {
        uint8_t     byteVersion;
        uint8_t     byteResult;
        uint8_t     byteReserved;
        uint8_t     byteAddressType;
        uint32_t	ulAddressIPv4;
        uint16_t	usPort;
    };

    struct UDPDatagramHeader
    {
        uint16_t	usReserved;
        uint8_t     byteFragment;
        uint8_t     byteAddressType;
        uint32_t	ulAddressIPv4;
        uint16_t	usPort;
    };
#pragma pack(pop)
}

/**
 * @class ProxyManager
 * Socks5-client for linux with supporting CONNECT and UDP_ASSOCIATE commands.
 */
class ProxyManager
{
public:
    ProxyManager() {}
    ~ProxyManager();
    /**
     * Connect to proxy-server.
     * @param ip IP address of proxy server.
     * @param port port of proxy server.
     * @param user login of proxy server or empty string if proxy without auth
     * @param password password of proxy server or empty string if proxy without auth
     * @param proxyMode mode of proxy. Socks5::PROXY_MODE::CONNECTION (TCP connect) or Socks5::PROXY_MODE::UDP_ASSOCIATE (UDP connect).
     * @param dstIP destination IP address (for CONNECTION mode).
     * @param dstPort destination port (for CONNECTION mode).
     * @return true if successful, false if connect was failed.
     */
    bool connectToProxy(std::string ip, uint16_t port, std::string user, std::string password, Socks5::PROXY_MODE proxyMode, std::string dstIP = "", uint16_t dstPort = 0);
    /**
     * Close connection to proxy server.
     */
    void closeConnection();
    /**
     * Send data to destination server through proxy server.
     * @param packet pointer to data array.
     * @param dataLength length of data array.
     * @param ip destination IP address (for UDP_ASSOCIATE mode).
     * @param port destination port (for UDP_ASSOCIATE mode).
     * @return length of sent data or -1 if error.
     */
    int32_t send(char* packet, uint16_t dataLength, std::string ip, uint16_t port);
    /**
     * Send data to destination server through proxy server.
     * @param packet pointer to data array.
     * @param dataLength length of data array.
     * @param host destination host (binary format).
     * @param port destination port (for UDP_ASSOCIATE mode).
     * @return length of sent data or -1 if error.
     */
    int32_t send(char* packet, uint16_t dataLength, int32_t host = 0, uint16_t port = 0);
    /**
     * Read data from destination server through proxy server.
     * @param data pointer to data array
     * @param bufferSize maximum size of data array
     * @param binAddres pointer to variable for write destination host address (binary format, for UDP_ASSOCIATE mode).
     * @param port pointer to variable for write destination host port (for UDP_ASSOCIATE mode).
     * @return length of recevied data or -1 if error.
     * @note Proxy socket is non blocking for UDP_ASSOCIATE mode.
     */ 
    int32_t read(char* data, uint16_t bufferSize, uint32_t* binAddres = 0, uint16_t* port = 0);
    /**
     * Waiting (with timeout) send or/and receive data. Only for UDP_ASSOCIATE mode.
     * @param waitMode pointer to bit-mask of waiting mode.
     * @param timeout timeout in mseconds.
     * @return 0 if success, -1 if error.
     */
    int32_t udpSocketWait(uint32_t *waitMode, uint32_t timeout);
    /**
     * Gets last error code.
     * @return error code.
     */
    Socks5::PROXY_ERROR lastErrorCode();
    /**
     * Gets error string by error code.
     * @param errorCode error code.
     * @return error string
     * @note this is static function.
     */ 
    static std::string getErrorString(Socks5::PROXY_ERROR errorCode);
    /**
     * Some proxy-server don`t adhere to RFC and give invalid address for udp asscotiation.
     * Therefore we must use main address forced in this cases.
     * @param _isForceMainAddress true if proxy don`t adhere to RFC, false if else.
     */
    static inline void setForceMainAddress(bool _isForceMainAddress) { isForceMainAddress = _isForceMainAddress; }

private:
    bool udpAssociate(unsigned long mainProxyAddr);
    bool connectionCommand(std::string dstIP, uint16_t dstPort);
    unsigned int tcpConnection = 0;
    unsigned int udpConnection = 0;
    sockaddr_in udpProxyAddr = { 0 };
    Socks5::PROXY_ERROR errorCode = Socks5::PROXY_ERROR::SUCCESS;
    Socks5::PROXY_MODE proxyMode = Socks5::PROXY_MODE::CONNECTION;
    bool bConnected = false;

    // Some proxy-servers don`t adhere to RFC
    // and give invalid address with udp association
    static bool isForceMainAddress;
};

#endif
