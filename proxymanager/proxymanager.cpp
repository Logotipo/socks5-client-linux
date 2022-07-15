#include "proxymanager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

bool ProxyManager::isForceMainAddress = false;

ProxyManager::~ProxyManager()
{
	closeConnection();
}

bool ProxyManager::connectToProxy(std::string ip, uint16_t port, std::string user, std::string password, Socks5::PROXY_MODE proxyMode, std::string dstIP, uint16_t dstPort)
{
	this->proxyMode = proxyMode;
	if ((proxyMode == Socks5::PROXY_MODE::CONNECTION || proxyMode == Socks5::PROXY_MODE::BIND) &&
		(dstIP.length() < 7 || dstPort == 0))
	{
		errorCode = Socks5::PROXY_ERROR::DST_HOST;
		return false;
	}

	tcpConnection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	unsigned long mainProxyAddr = inet_addr(ip.c_str());
	struct sockaddr_in hostAddr;
	hostAddr.sin_family = AF_INET;
	hostAddr.sin_addr.s_addr = mainProxyAddr; // proxy IP
	hostAddr.sin_port = htons(port);		  // proxy port

	if (connect(tcpConnection, (sockaddr*)(&hostAddr), sizeof(hostAddr)) == 0)
	{
		Socks5::AuthRequestHeader auth_req_head;
		memset(&auth_req_head, 0, sizeof(Socks5::AuthRequestHeader));
		auth_req_head.byteVersion = 0x05;
		auth_req_head.byteAuthMethodsCount = 0x01;
		if (user.empty() || password.empty())
			auth_req_head.byteMethods[0] = 0x00;
		else
			auth_req_head.byteMethods[0] = 0x02;

		if (::send(tcpConnection, (const char*)&auth_req_head, sizeof(Socks5::AuthRequestHeader), 0) > 0)
		{
			char proxyResponse[sizeof(Socks5::AuthRespondHeader) + 8];
			memset(proxyResponse, 0, sizeof(proxyResponse));
			int32_t responseLength = recv(tcpConnection, proxyResponse, sizeof(proxyResponse), 0);
			if (responseLength > 0)
			{
				Socks5::AuthRespondHeader auth_resp_head;
				memcpy(&auth_resp_head, proxyResponse, sizeof(Socks5::AuthRespondHeader));
				if (auth_resp_head.byteVersion != 0x05)
				{
					errorCode = Socks5::PROXY_ERROR::PROTOCOL;
					close(tcpConnection);
					return false;
				}
				if (auth_resp_head.byteAuthMethod == 0x00)
				{
					if (proxyMode == Socks5::PROXY_MODE::CONNECTION)
						return connectionCommand(dstIP, dstPort);
					else if (proxyMode == Socks5::PROXY_MODE::UDP_ASSOCIATE)
						return udpAssociate(mainProxyAddr);
					else
					{
						close(tcpConnection);
						return false;
					}
				}
				else if (auth_req_head.byteMethods[0] == 0x02 && auth_resp_head.byteAuthMethod == 0x02)
				{
					uint8_t userLength = static_cast<uint8_t>(user.length());
					uint8_t passwordLength = static_cast<uint8_t>(password.length());
					uint8_t* auth_data = new uint8_t[3 + userLength + passwordLength];
					if (auth_data)
					{
						auth_data[0] = 0x01;//the current version of the subnegotiation
						auth_data[1] = userLength;
						memcpy(&auth_data[2], user.c_str(), userLength);
						auth_data[2 + userLength] = passwordLength;
						memcpy(&auth_data[3 + userLength], password.c_str(), passwordLength);
						if (::send(tcpConnection, (const char*)auth_data, 3 + userLength + passwordLength, 0) > 0)
						{
							delete[] auth_data;
							char proxyAuthResponse[sizeof(Socks5::AuthUPRespondtHeader)];
							responseLength = recv(tcpConnection, proxyAuthResponse, sizeof(proxyAuthResponse), 0);
							if (responseLength > 0)
							{
								Socks5::AuthUPRespondtHeader auth_up_resp_head;
								memcpy(&auth_up_resp_head, proxyAuthResponse, sizeof(Socks5::AuthUPRespondtHeader));
								if (auth_up_resp_head.byteVersion != 0x01)
								{
									errorCode = Socks5::PROXY_ERROR::PROTOCOL;
									close(tcpConnection);
									return false;
								}
								if (auth_up_resp_head.byteRespondCode == 0x00)
								{
									if (proxyMode == Socks5::PROXY_MODE::CONNECTION)
										return connectionCommand(dstIP, dstPort);
									else if (proxyMode == Socks5::PROXY_MODE::UDP_ASSOCIATE)
										return udpAssociate(mainProxyAddr);
									else
									{
										close(tcpConnection);
										return false;
									}
								}
								else
								{
									errorCode = Socks5::PROXY_ERROR::SIGNIN;
									close(tcpConnection);
									return false;
								}
							}
							else
							{
								errorCode = Socks5::PROXY_ERROR::NETWORK;
								close(tcpConnection);
								return false;
							}
						}
						else
						{
							free(auth_data);
							errorCode = Socks5::PROXY_ERROR::NETWORK;
							close(tcpConnection);
							return false;
						}
					}
					else
					{
						errorCode = Socks5::PROXY_ERROR::MEMORY;
						close(tcpConnection);
						return false;
					}
				}
				else
				{
					errorCode = Socks5::PROXY_ERROR::AUTH_METHOD;
					close(tcpConnection);
					return false;
				}
			}
			else
			{
				errorCode = Socks5::PROXY_ERROR::PROTOCOL;
				close(tcpConnection);
				return false;
			}
		}
		else
		{
			errorCode = Socks5::PROXY_ERROR::NETWORK;
			close(tcpConnection);
			return false;
		}

	}
	else
	{
		errorCode = Socks5::PROXY_ERROR::CONNECTION;
		close(tcpConnection);
		return false;
	}
}

void ProxyManager::closeConnection()
{
	if (!bConnected)
		return;

	if(proxyMode == Socks5::PROXY_MODE::UDP_ASSOCIATE)
		close(udpConnection);

	close(tcpConnection);
	bConnected = false;
}

bool ProxyManager::connectionCommand(std::string dstIP, uint16_t dstPort)
{
	Socks5::ConnectRequestHeader connect_command_head;
	memset(&connect_command_head, 0, sizeof(Socks5::ConnectRequestHeader));
	connect_command_head.byteVersion = 5;
	connect_command_head.byteCommand = 1; // tcp connection = 1, tcp binding = 2,  udp = 3
	connect_command_head.byteReserved = 0;
	connect_command_head.byteAddressType = 1; // IPv4=1, domain name = 3, IPv6 = 4
	connect_command_head.ulAddressIPv4 = inet_addr(dstIP.c_str());
	connect_command_head.usPort = htons(dstPort);

	if (::send(tcpConnection, (const char*)&connect_command_head, sizeof(Socks5::ConnectRequestHeader), 0) > 0)
	{
		char proxyResponse[sizeof(Socks5::ConnectRespondHeader) + 8];
		memset(proxyResponse, 0, sizeof(proxyResponse));
		int32_t responseLength = recv(tcpConnection, proxyResponse, sizeof(proxyResponse), 0);
		if (responseLength > 0)
		{
			Socks5::ConnectRespondHeader connect_command_resp_head;
			memcpy(&connect_command_resp_head, proxyResponse, sizeof(Socks5::ConnectRespondHeader));
			if (connect_command_resp_head.byteVersion == 0x05 && connect_command_resp_head.byteResult == 0x00)
			{
				bConnected = true;
				return true;
			}
			else
			{
				if (connect_command_resp_head.byteResult < 9)
					errorCode = static_cast<Socks5::PROXY_ERROR>((uint8_t)Socks5::PROXY_ERROR::SIGNIN + connect_command_resp_head.byteResult);
				else
					errorCode = Socks5::PROXY_ERROR::UNKNOW;

				close(tcpConnection);
				return false;
			}
		}
		else
		{
			errorCode = Socks5::PROXY_ERROR::NETWORK;
			close(tcpConnection);
			return false;
		}
	}
	else
	{
		errorCode = Socks5::PROXY_ERROR::NETWORK;
		close(tcpConnection);
		return false;
	}
}

bool ProxyManager::udpAssociate(unsigned long mainProxyAddr)
{
	Socks5::ConnectRequestHeader udp_accoc_head;
	memset(&udp_accoc_head, 0, sizeof(Socks5::ConnectRequestHeader));
	udp_accoc_head.byteVersion = 5;
	udp_accoc_head.byteCommand = 3; // tcp connection = 1, tcp binding = 2,  udp = 3
	udp_accoc_head.byteReserved = 0;
	udp_accoc_head.byteAddressType = 1; // IPv4=1, domain name = 3, IPv6 = 4
	udp_accoc_head.ulAddressIPv4 = 0;
	udp_accoc_head.usPort = 0;

	if (::send(tcpConnection, (const char*)&udp_accoc_head, sizeof(Socks5::ConnectRequestHeader), 0) > 0)
	{
		char proxyResponse[sizeof(Socks5::ConnectRespondHeader) + 8];
		memset(proxyResponse, 0, sizeof(proxyResponse));
		int32_t responseLength = recv(tcpConnection, proxyResponse, sizeof(proxyResponse), 0);
		if (responseLength > 0)
		{
			Socks5::ConnectRespondHeader udp_accoc_resp_head;
			memcpy(&udp_accoc_resp_head, proxyResponse, sizeof(Socks5::ConnectRespondHeader));
			if (udp_accoc_resp_head.byteVersion == 0x05 && udp_accoc_resp_head.byteResult == 0x00)
			{
				if (!isForceMainAddress)
					udpProxyAddr.sin_addr.s_addr = udp_accoc_resp_head.ulAddressIPv4;
				else
					udpProxyAddr.sin_addr.s_addr = mainProxyAddr;

				udpProxyAddr.sin_family = AF_INET;
				udpProxyAddr.sin_port = udp_accoc_resp_head.usPort;
				udpConnection = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				unsigned long nonblock = 1;
				ioctl(udpConnection, FIONBIO, &nonblock);
				struct sockaddr_in localaddr;
				localaddr.sin_family = AF_INET;
				localaddr.sin_addr.s_addr = INADDR_ANY;
				localaddr.sin_port = 0; // Any local port will do
				if (!bind(udpConnection, (struct sockaddr*)&localaddr, sizeof(localaddr)))
				{
					bConnected = true;
					return true;
				}
				else
				{
					errorCode = Socks5::PROXY_ERROR::UDP_BIND;
					close(tcpConnection);
					return false;
				}
			}
			else
			{
				if (udp_accoc_resp_head.byteResult < 9)
					errorCode = static_cast<Socks5::PROXY_ERROR>((uint8_t)Socks5::PROXY_ERROR::SIGNIN + udp_accoc_resp_head.byteResult);
				else
					errorCode = Socks5::PROXY_ERROR::UNKNOW;

				close(tcpConnection);
				return false;
			}
		}
		else
		{
			errorCode = Socks5::PROXY_ERROR::NETWORK;
			close(tcpConnection);
			return false;
		}
	}
	else
	{
		errorCode = Socks5::PROXY_ERROR::NETWORK;
		close(tcpConnection);
		return false;
	}
}

int32_t ProxyManager::send(char* packet, uint16_t dataLength, std::string ip, uint16_t port)
{
	if (!bConnected)
		return -1;

	if (proxyMode == Socks5::PROXY_MODE::CONNECTION)
	{
		return ::send(tcpConnection, (const char*)packet, dataLength, 0);
	}
	else if (proxyMode == Socks5::PROXY_MODE::UDP_ASSOCIATE)
	{
		if (!ip.empty() && port != 0)
		{
			return send(packet, dataLength, inet_addr(ip.c_str()), port);
		}
		else return -1;
	}
	else return -1;
}

int32_t ProxyManager::send(char* packet, uint16_t dataLength, int32_t host, uint16_t port)
{
	if (!bConnected)
		return -1;

	if (proxyMode == Socks5::PROXY_MODE::CONNECTION)
	{
		return ::send(tcpConnection, (const char*)packet, dataLength, 0);
	}
	else if (proxyMode == Socks5::PROXY_MODE::UDP_ASSOCIATE)
	{
		if (host != 0 && port != 0)
		{
			size_t alloc_size = dataLength + sizeof(Socks5::UDPDatagramHeader) + 1;
			char* allData = new char[alloc_size];
			if (allData)
			{
				Socks5::UDPDatagramHeader* send_head = (Socks5::UDPDatagramHeader*)allData;
				memset(allData, 0, alloc_size);
				send_head->usReserved = 0;
				send_head->byteFragment = 0;
				send_head->byteAddressType = 1;
				send_head->ulAddressIPv4 = host;
				send_head->usPort = htons(port);
				memcpy(&allData[sizeof(Socks5::UDPDatagramHeader)], packet, dataLength);
				int32_t result = ::sendto(udpConnection, allData, dataLength + sizeof(Socks5::UDPDatagramHeader), 0, (sockaddr*)&udpProxyAddr, sizeof(udpProxyAddr));
				delete[] allData;

				if (result > sizeof(Socks5::UDPDatagramHeader))
					return result - sizeof(Socks5::UDPDatagramHeader);
				else
					return result;
			}
			else return -1;
		}
		else return -1;
	}
	else return -1;
}

int32_t ProxyManager::read(char* data, uint16_t bufferSize, uint32_t* binAddres, uint16_t* port)
{
	if (!bConnected)
		return -1;

	if (proxyMode == Socks5::PROXY_MODE::CONNECTION)
	{
		return recv(tcpConnection, data, bufferSize, 0);
	}
	else if (proxyMode == Socks5::PROXY_MODE::UDP_ASSOCIATE)
	{
		uint16_t inputDataSize = bufferSize + sizeof(Socks5::UDPDatagramHeader);
		char* inputData = new char[inputDataSize];
		if (inputData)
		{
			memset(inputData, 0, inputDataSize);
			int32_t result = recv(udpConnection, inputData, inputDataSize, 0);
			if (result > (int32_t)sizeof(Socks5::UDPDatagramHeader))
			{
				Socks5::UDPDatagramHeader* udpDataHeader = (Socks5::UDPDatagramHeader*)inputData;
				if (binAddres != 0)
					*binAddres = udpDataHeader->ulAddressIPv4;
				if (port != 0)
					*port = udpDataHeader->usPort;
				memcpy(data, inputData + sizeof(Socks5::UDPDatagramHeader), result - sizeof(Socks5::UDPDatagramHeader));
				delete[] inputData;
				return (result - sizeof(Socks5::UDPDatagramHeader));
			}
			else
			{
				delete[] inputData;
				return -1;
			}
		}
		else return -1;
	}
	else return -1;
}

int32_t ProxyManager::udpSocketWait(uint32_t *waitMode, uint32_t timeout)
{
	fd_set readSet, writeSet;
	struct timeval timeVal;
	int selectCount;

	timeVal.tv_sec = timeout / 1000;
	timeVal.tv_usec = (timeout % 1000) * 1000;

	FD_ZERO(&readSet);
	FD_ZERO(&writeSet);

	if (*waitMode & static_cast<uint32_t>(Socks5::PROXY_WAIT_MODE::PROXY_WAIT_SEND))
		FD_SET(udpConnection, &writeSet);

	if (*waitMode & static_cast<uint32_t>(Socks5::PROXY_WAIT_MODE::PROXY_WAIT_RECEIVE))
		FD_SET(udpConnection, &readSet);

	selectCount = select(udpConnection + 1, &readSet, &writeSet, NULL, &timeVal);

	if (selectCount < 0)
		return -1;

	*waitMode = static_cast<uint32_t>(Socks5::PROXY_WAIT_MODE::PROXY_WAIT_NONE);

	if (selectCount == 0)
		return 0;

	if (FD_ISSET(udpConnection, &writeSet))
		*waitMode |= static_cast<uint32_t>(Socks5::PROXY_WAIT_MODE::PROXY_WAIT_SEND);

	if (FD_ISSET(udpConnection, &readSet))
		*waitMode |= static_cast<uint32_t>(Socks5::PROXY_WAIT_MODE::PROXY_WAIT_RECEIVE);

	return 0;
}

Socks5::PROXY_ERROR ProxyManager::lastErrorCode() {
	return errorCode;
}

std::string ProxyManager::getErrorString(Socks5::PROXY_ERROR errorCode) {
	const std::string errorStrings[] = {
		"No error",
		"Connection to proxy server attempt failed",
		"Error while sending data to the proxy server",
		"Response inconsistency with the protocol",
		"Invalid authentication method",
		"Failed to create UDP socket",
		"Username and/or password not set",
		"Dynamic memory allocation error",
		"Destination host not specified (for CONNECT and BIND commands)",
		"Invalid username and/or password from the proxy",
		"General proxy error",
		"Connection not allowed by proxy server rule set",
		"The network is unavailable on the side of the proxy server",
		"Proxy server failed to connect to destination host",
		"Connection refused",
		"TTL expired",
		"The command is not supported by the proxy server",
		"The specified address type is not supported by the proxy server",
		"Unknown error"
	};
	uint8_t iErrorCode = static_cast<uint8_t>(errorCode);
	if (iErrorCode >= 19)
		iErrorCode = 18;
	return errorStrings[iErrorCode];
}