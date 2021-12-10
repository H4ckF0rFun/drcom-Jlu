
#include "common.h"
#include "md5.h"


struct sockaddr_in drcom_auth_server = { 0 };
int s = 0;

char username[36] = { 0 };
char password[36] = { 0 };


long get_sysuptime()
{
	struct sysinfo si;
  	sysinfo(&si);
  return si.uptime;
}
int DrcomCRC32(int a1, char*a2, int a3)
{
	int i; // [esp+8h] [ebp-8h]

	for (i = 0; a3 / 4 > i; ++i)
		a1 ^= *(uint32_t *)(a2 + 4 * i);
	return a1;
}


struct LoginSuccess
{
	unsigned char statu;
	uint32_t unknown;
	uint32_t unknown1;
	uint32_t unknown2;
	uint32_t unknown_flag;
	char unknown_[6];
	uint32_t auth_token[4];
}
__attribute__((packed));


struct Response
{
	unsigned char  statu;
	unsigned char  sendcount;
	unsigned short sendTimeStamp;
	unsigned int auth_data;
	unsigned short bRorEncrypt;
	unsigned short AuthProtoVerMinor;
	unsigned short AuthProtoVerMajor;
	unsigned short unknown;
	unsigned int __unknown;
	unsigned int AuthHostIP;

	unsigned short unknown1;
	unsigned short unknown2;
	unsigned short unknown3;
	unsigned short unknown4;
	unsigned short unknown5;
	unsigned short unknown6;
	unsigned short unknown7;
	unsigned short unknown8;
	unsigned short unknown9;
	unsigned short sysAuthOpt;			//as_EncryptMode == sysAuthOpt & 0x8000
}__attribute__((packed));


uint32_t HostInfoBuffer[] =				//这里储存的只是一些和系统有关的信息
{
	0x61636f6c, 0x736f686c, 0x6f6c2e74, 0x646c6163,
	0x69616d6f, 0x0000006e, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x01000000, 0x4f437244, 0x07cf004d,
	0x2e320068, 0x38312e36, 0x3436312d, 0x356c652e,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x65336564, 0x33346462,
	0x32633563, 0x38643032, 0x39356434, 0x33623564,
	0x66343062, 0x61383039, 0x33366431, 0x38366638,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000
};

struct HostInfo
{
	char HostName[32];					//localhost.localdomain
	uint32_t zero;						//0x00000000
	uint32_t AuthDHCPSvr;				//0x00000000
	char _zero[28];						//0x0000000

	uint32_t osVersion;					//0x1000000
	uint32_t UserVersion;					//0x4F437244
	uint32_t host_info_unknown_member;		//0x07CF004D
	uint16_t KernelVersion;
	char HostDetail[54];				//2.6.18-164.el5
	char AuthModuleHash[64];			//de3ebd43c5c220d84d59d5b3b04f908a1d638f68

}__attribute__((packed));



struct HostInfo *pHostInfo = 0;


struct NameAndPasswd
{
	uint16_t unknown ;					//+0 0
	uint8_t unknown1;					//+2
	uint8_t user_len_add_20;			//+3 用户名长度+20
	uint32_t _0_md5[4];				//+4 md5
	char authUser[36] ;				//+20 保存用户名

	uint8_t control_Check_statu;		//+56
	uint8_t unknown2 ;					//+57

	unsigned char AuthMac[6];		//+58
	
	uint32_t _1_md5[4];				//+64

	uint8_t IPCount;					//+80
	uint32_t IP[4];					//+81

	uint16_t unknown_1;					//+97
	uint8_t unknown_2;					//+99
	uint8_t unknown_3;					//+100
	
	uint32_t md5_1;					//+101
	uint8_t unknown_uint8_t;				//+105
	uint32_t zero;						//+106
	char HostInfo[200] ;			//+110
	uint8_t mode;						//+310
	uint8_t unused;					//+311
}__attribute__((packed));


unsigned char AuthHostMac[6] = { 0 };

uint8_t AuthIPCount = 0;
uint32_t AuthIPS[4] ;

uint32_t authToken[4] = { 0 };
uint32_t md5Token[4] = { 0 };

void SendNameAndPasswd(struct Response*pResponse)			//发送账号和密码
{
	char buffer[1600] = { 0 };
	buffer[0] = 3;										 // +0x0      3
	buffer[1] = 1;										// +0x1      1
	int passwd_len = strlen(password);
	int buffer_len = 0;
	int*md5;
	int i;
	printf("\nStatuCode:%d", pResponse->statu);
	printf("\nSendCount:%d", pResponse->sendcount);
	printf("\nsendTimeStamp:%d", pResponse->sendTimeStamp);
	printf("\nAuthProtoVer %d.%d", pResponse->AuthProtoVerMajor, pResponse->AuthProtoVerMinor);
	printf("\nAuthHost:%s", inet_ntoa(*(struct in_addr*)(&pResponse->AuthHostIP)));
	printf("\nbRorEncrypt?:%d", pResponse->bRorEncrypt);

	*(uint32_t*)&buffer[2] = pResponse->auth_data;			// +0x2      auth_data

	memcpy(&buffer[6], password, passwd_len);			// +0x6      passwd
	buffer_len = passwd_len + 6;

	md5 = md5Encode(buffer, passwd_len + 6);			// total len 6 + passwd(16) == 22

	memcpy(md5Token, md5, 16);							//后面发送ping会需要这个东西


	char encryptAutMac[6] = { 0 };
	for (i = 0; i <= 5; ++i)
		encryptAutMac[i] = AuthHostMac[i] ^ *((uint8_t *)md5 + i);


	struct NameAndPasswd senddata;
	memset(&senddata, 0, sizeof(senddata));


	senddata.unknown = 259;
	senddata.unknown1 = 0;
	senddata.user_len_add_20 = strlen(username) + 20;

	memcpy(&senddata._0_md5, md5, 16);					//拷贝md5
	memcpy(senddata.authUser, username,36);				//拷贝用户名
	memcpy(senddata.AuthMac, encryptAutMac, 6);			//拷贝加密后的mac

	senddata.control_Check_statu = 0;
	senddata.unknown2 = 0;

	memset(buffer, 0, sizeof(buffer));
	buffer[0] = 1;
	memcpy(&buffer[1], password, passwd_len);
	*(uint32_t *)&buffer[passwd_len + 1] = pResponse->auth_data;
	buffer_len = passwd_len + 9;
	md5 = md5Encode(buffer, passwd_len + 9);
	memcpy(&senddata._1_md5, md5, 16);

	//拷贝IP
	senddata.IPCount = 1;
	memcpy(&senddata.IP, AuthIPS, 16);

	senddata.unknown_1 = 20;
	senddata.unknown_2 = 7;
	senddata.unknown_3 = 11;

	md5 = md5Encode(&senddata, 101);

	memcpy(&senddata.unknown_1, md5, 4);
	senddata.md5_1 = md5[1];
	senddata.zero = 0;
	senddata.unused = 0;
	memcpy(senddata.HostInfo, pHostInfo, 200);		//拷贝HostInfo;


	senddata.mode = 2;

	memset(buffer, 0, sizeof(buffer));
	buffer_len = 312;
	memcpy(buffer, &senddata, 312u);

	if (pResponse->bRorEncrypt)
	{
		unsigned char*pBufferTail = (unsigned char*)&buffer[buffer_len];
		int passwd_len = strlen(password);

		for (i = 0; i < passwd_len; ++i)
		{
			pBufferTail[i + 2] = password[i] ^ *((uint8_t *)&senddata._0_md5 + i);

			pBufferTail[i + 2] = ((pBufferTail[i + 2]) << 3) | ((pBufferTail[i + 2]) >> 5);
		}
		buffer_len += passwd_len + 2;
	}
	//
	char* buffer_tail = &buffer[buffer_len];
	buffer[buffer_len] = 2;									// +0x0       2
	buffer_tail[1] = 12;									// +0x1       12
	*(uint32_t *)(buffer_tail + 2) = 285681153;				// +0x2       285681153
	*((uint16_t *)buffer_tail + 3) = 0;							// +0x6       dhcp_option

	char* _mac_start = buffer_tail + 8;						// +0x8       AuthHostMac(6uint8_ts)
	*((uint32_t *)buffer_tail + 2) = *(uint32_t *)AuthHostMac;	// mac地址6个字节
	*((uint16_t *)_mac_start + 2) = *(uint16_t *)&AuthHostMac[4];
	buffer_len += 14;

	buffer_len = 4 * ((buffer_len + 3) / 4);				// 补成4的整数倍
	int crc32 = DrcomCRC32(1234, buffer, buffer_len);

	*(uint32_t *)(buffer_tail + 2) = 1968 * crc32;				// +0x2      CRC32

	sendto(s, buffer, buffer_len, 0, (struct sockaddr*)&drcom_auth_server, sizeof(drcom_auth_server));
}


struct PingPacket
{
	unsigned char cmd;
	uint32_t md5[4];
	char unknown[3];
	uint32_t authToken[4];

	uint16_t timeStamp;
	uint32_t InternetAccessControl;
}__attribute__((packed));

void SendPing()
{
	struct PingPacket Packet = { 0 };
	Packet.cmd = 0xff;
	Packet.timeStamp = time(0);

	memcpy(Packet.authToken, authToken, 16);
	memcpy(Packet.md5, md5Token,16);

	printf("\n[#]Send ping.");
	sendto(s, (char*)&Packet, 38, 0, (struct sockaddr*)&drcom_auth_server, sizeof(drcom_auth_server));
}

unsigned char bLoginSuccess = 0;

unsigned int nSendPingCount = 0;


void onLoginSeccess(struct LoginSuccess*pSuc)
{
	printf("\n[#]login success Statu:%d", pSuc->statu);
	printf("\n[#]login_success Token:%08x %08x %08x %08x", pSuc->auth_token[0], pSuc->auth_token[1], pSuc->auth_token[2], pSuc->auth_token[3]);
	memcpy(authToken, pSuc->auth_token,16);
	
	bLoginSuccess = 1;

	if (nSendPingCount == 0)
	{
		SendPing();
		nSendPingCount++;
	}
}


struct AuthSvrRetData
{
	unsigned char statu;
	char unknown_0[3];
	unsigned char cmd;
	unsigned char ping_interval;

	char unknown_1[26];

	unsigned int realTimeOnlineStatu[8];
}__attribute__((packed));


void DrcomAuthSvrReturnDataHandler(char* buffer, int len)
{
	struct AuthSvrRetData*pData = (struct AuthSvrRetData*)buffer;
	switch (pData->cmd)
	{
	case 6:
		printf("\n[#]Handle_ping_interval cmd:%d", pData->cmd);
		printf("\n[#]Handle_ping_interval ping_interval:%d", pData->ping_interval);
		nSendPingCount--;
		break;
	default:
		break;
	}
}

void MsgHandler(char*buffer, int len)
{
	switch (*buffer)
	{
	case 2:
		printf("\n[#]send username and password.");
		SendNameAndPasswd((struct Response*)buffer);
		break;
	case 4:
		printf("\n[#]auth success!");
		onLoginSeccess((struct LoginSuccess*)buffer);
		break;
	case 7:
		printf("\n[#]AuthSvrRetData");
		DrcomAuthSvrReturnDataHandler(buffer, len);
		break;
	default:
		printf("\nUnknown StatuCode:%d", *buffer);
		break;
	}
}
long LastRecvTime = 0;

void BeginRecv()
{
	printf("\n[#]begin recv data.........");

	int addrlen,nRead;
	char buffer[1600] = { 0 };
	struct sockaddr_in sockaddr = { 0 };

	while (1)
	{
		addrlen = sizeof(sockaddr);
		nRead = 0;
		memset(&sockaddr, 0, sizeof(sockaddr));

		nRead = recvfrom(s, buffer, 1600, 0, (struct sockaddr*)&sockaddr, &addrlen);
		if (nRead <= 0)
		{
			putchar('.');
			sleep(2);
		}
		else
		{
			LastRecvTime = get_sysuptime();
			printf("\n==================recv data from %s  size:%d==================", inet_ntoa(sockaddr.sin_addr), nRead);
			//处理发来的数据
			MsgHandler(buffer, nRead);
		}

		if(get_sysuptime()<LastRecvTime)
		{
			LastRecvTime = get_sysuptime();		//可能绕了一个圈吧;
		}
		//只要距离上一次接收数据60s,就认为是超时
		if ((get_sysuptime() - LastRecvTime) >= (60))
		{
			//超时,认为是掉线.
			bLoginSuccess = 0;
			return;//return之后直接重新登录
		}

		if (bLoginSuccess)
		{
			//过了19s,发送一次ping
			if ((get_sysuptime() - LastRecvTime) >= (19) && nSendPingCount == 0)
			{
				nSendPingCount++;
				SendPing();
			}
		}
	}
	return;
}



//第一次发送的数据包
struct Login
{
	unsigned char command;
	unsigned char count;
	unsigned short timestamp;
	unsigned int drcom_client_ker_version;
	unsigned char _zero[12];
}__attribute__((packed));


int packetSendCount = 0;

int main()
{
	//输出无缓冲
	setvbuf(stdout,0,2,0);

	FILE*fp = fopen("userinfo.txt", "r");
	if (fp == 0)
	{
		printf("couldn't open userinfo.txt\n");
		return 0;
	}
	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));

	fscanf(fp, "%s", username);
	fscanf(fp, "%s", password);

	char sz_IP[16] = { 0 };
	fscanf(fp, "%s", sz_IP);

	char sz_mac[64] = { 0 };
	fscanf(fp, "%s", sz_mac);
	fclose(fp);

	pHostInfo = (struct HostInfo*)HostInfoBuffer;
	
	//用户信息
	printf("\nusername:%s", username);
	printf("\npasswrod:%s", password);
	printf("\nbind IP: %s",sz_IP);
	printf("\nbind mac:");

	//encrypt_passwd((unsigned int*)password);
	//IP,
	AuthIPS[0] = inet_addr(sz_IP);
	uint32_t auth_host_mac[6];
	sscanf(sz_mac,"%x%*c%x%*c%x%*c%x%*c%x%*c%x", &auth_host_mac[0], &auth_host_mac[1], &auth_host_mac[2], &auth_host_mac[3], &auth_host_mac[4], &auth_host_mac[5]);
	int i;
	for(i = 0;i<6;i++)
	{
		AuthHostMac[i] = auth_host_mac[i];
		printf("%02x ",AuthHostMac[i]);
	}

	//验证服务器信息
	drcom_auth_server.sin_family = AF_INET;
	drcom_auth_server.sin_port = ntohs(61440);
	drcom_auth_server.sin_addr.s_addr = inet_addr("10.100.61.3");
	
	while (1)
	{
		struct Login Packet = { 0 };
		Packet.command = 1;
		Packet.count = packetSendCount++;
		Packet.timestamp = time(0);
		Packet.drcom_client_ker_version = 104;

		struct sockaddr_in local_addr = { 0 };
		local_addr.sin_addr.s_addr = INADDR_ANY;
		local_addr.sin_family = AF_INET;
		local_addr.sin_port = htons(0xf000);

		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (0 == bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr)))
		{
			printf("\n[#]bind socket 0.0.0.0:61440 success!");
		}
		else
		{
			printf("\n[#]bind socket 0.0.0.0:61440 fail!");
		}

		//设置socket为非阻塞模式
		int flag = fcntl(s,F_GETFL,0);
		fcntl(s,F_SETFL,flag|O_NONBLOCK);
		//int optval[2];
		//optval[0] = 0;
		//optval[1] = 100000000;

		//linux 下 1 是 SOL_SOCKET
		//setsockopt(s, SOL_SOCKET, 21, (const char*)optval, 8);
		//(s, SOL_SOCKET, 20, (const char*)optval, 8);

		printf("\nbegin send packet");
		printf("\nCommand: %d", Packet.command);
		printf("\nCount: %d", Packet.count);
		printf("\nTimeStamp: %d", Packet.timestamp);
		printf("\nKernelVersion: %d", Packet.drcom_client_ker_version);
		nSendPingCount = 0;
		LastRecvTime = get_sysuptime();
		int nWriten = sendto(s, (char*)&Packet, 20, 0, (struct sockaddr*)&drcom_auth_server, sizeof(drcom_auth_server));
		BeginRecv();
		close(s);
	}
	return 0;
}

