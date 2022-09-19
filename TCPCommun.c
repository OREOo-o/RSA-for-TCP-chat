/*
	TCPCommun.c
	这里是TCP通信模块，负责聊天程序的连接及消息发送和接收。
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "TCPCommun.h"
#include "DESSecurity.h"

#define SERVERPORT 8888		//服务器监听端口
#define BACKLOG 5			//监听队列长度
#define BUFFERSIZE 1024		//缓冲区大小
#define DESKEYLENGTH 64		//DES密钥长度

//公钥结构体
struct PublicKey
{
	long nE;
	long nN;
};
//RSA参数
struct RSAParam
{
	long p;
	long q;
	long n;
	long f;
	long e;
	long d;
	long s;
};

void SecretChat(int sock, char ipaddr[], char chatkey[]);	//安全聊天
int TotalRecv(int sock, void* szBuffer, size_t length, int flag);	//接受完整消息
void DESAllocGener(int sock);		//生成并分配DES密钥
void DESAllocRecv(int sock);		//生成RSA公私钥并接收DES密钥
void RSAGetParam();			//初始化RSA参数
struct PublicKey GetPublicKey();	//获取当前使用的公钥
long RSAEncry(unsigned short nSource, struct PublicKey publickey);	//RSA加密
unsigned short RSADecry(long nSource);
unsigned long MulMod(unsigned long a, unsigned long b, unsigned long n);		//模乘运算
unsigned long PowMod(unsigned long base, unsigned long pow, unsigned long n);	//模幂运算
long RabinMillerKnl(unsigned long n);						//拉宾——米勒测试
long RabinMiller(unsigned long n, unsigned long loop);		//重复拉宾——米勒测试
unsigned long RandomPrime(char bits);					//质数生成函数
unsigned long Gcd(unsigned long p, unsigned long q);		//求最大公约数
unsigned long Enclid(unsigned long e, unsigned long t_n);	//生成私钥d

char chatkey[20] = "testtest";
struct RSAParam rsa = {0};	//RSA参数
struct PublicKey publickey;	//RSA公钥

//客户端连接服务器
int ClientToServer(char serverIpAddr[])
{
	int client;
	struct sockaddr_in serveraddr;

	//建立客户端socket
	if((client = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Create socket failed!");
		return 0;
	}

	//设置服务器地址结构
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(SERVERPORT);
	serveraddr.sin_addr.s_addr = inet_addr(serverIpAddr);

	//连接服务器
	if(connect(client, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) != 0)
	{
		perror("Client connect failed!");
		return 0;
	}
	printf("Connect Success!\n");

	//DES密钥分配
	DESAllocGener(client);

	//连接已经建立，开始聊天
	printf("Begin chat ...\n");
	SecretChat(client, serverIpAddr, chatkey);

	//关闭socket
	close(client);

	return 1;
}

//服务器连接客户端
int ServerToClient()
{
	int server, client, length;
	struct sockaddr_in localaddr;
	struct sockaddr_in remoteaddr;

	//建立服务器socket
	if((server = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Create socket failed!");
		return 0;
	}

	//设置服务器地址结构
	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(SERVERPORT);
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//绑定监听端口
	if(bind(server, (struct sockaddr*)&localaddr, sizeof(struct sockaddr)) == -1)
	{
		perror("Bind port failed!");
		return 0;
	}

	//开始监听
	if(listen(server, BACKLOG) == -1)
	{
		perror("Listen failed!");
		return 0;
	}
	printf("Listening...\n");

	//接收连接请求
	length = sizeof(struct sockaddr_in);
	if((client = accept(server, (struct sockaddr *)&remoteaddr, &length)) == -1)
	{
		perror("Accept socket failed!");
		return 0;
	}
	printf("Server: got connection from %s, port %d, socket %d\n", inet_ntoa(remoteaddr.sin_addr), ntohs(remoteaddr.sin_port), client);
	close(server);

	//DES密钥分配
	DESAllocRecv(client);

	//连接建立，开始聊天
	printf("Begin chat ...\n");
	SecretChat(client, inet_ntoa(remoteaddr.sin_addr), chatkey);

	//关闭socket
	close(client);

	return 1;
}

//安全聊天
void SecretChat(int sock, char ipaddr[], char chatkey[])
{
	pid_t pid;	//进程标识符
	char szInputBuffer[BUFFERSIZE], szRecvBuffer[BUFFERSIZE];
	int length = 0;

	//检查密钥的长度
	if(strlen(chatkey) != 8)
	{
		printf("key length error!\n");
		return ;
	}

	//创建子进程，进行并发通信
	//如果pid=0,则表示为子进程,否则为父进程
	//父进程负责接收消息后解密并输出到标准输出，子进程负责获取标准输入加密并发送
	pid = fork();
	if(pid != 0)
	{
		//父进程,负责接收消息
		while(1)
		{
			length = recv(sock, szRecvBuffer, BUFFERSIZE, 0);
			if(length <= 0)
			{
				printf("Receive failed!\n");
			}
			else
			{
				DESDecry(szRecvBuffer, chatkey);
				printf("Receive message from<%s>: %s\n", ipaddr, szRecvBuffer);
			}

			if(!strcmp(szRecvBuffer, "quit"))
			{
				printf("Quit chat!\n");
				break;
			}
		}
	}
	else
	{
		//子进程，负责发送消息
		while(1)
		{
			scanf("%s", szInputBuffer);
			if(strlen(szInputBuffer) <= 0)
			{
				printf("Input error!\n");
				continue;
			}
			DESEncry(szInputBuffer, chatkey);
			length = send(sock, szInputBuffer, strlen(szInputBuffer)+1, 0);
			if(length <= 0)
			{
				printf("Send failed!\n");
			}
			
			if(!strcmp(szInputBuffer, "quit"))
			{
				printf("Quit chat!\n");
				break;
			}
		}
	}
}

//完整接受消息
int TotalRecv(int sock, void* szBuffer, size_t length, int flag)
{
	int nRealSize = 0;
	int nReal = 0;

	//循环接受消息
	while(nReal != -1)
	{
		nReal = recv(sock, ((char*)szBuffer)+nRealSize, length - nRealSize, flag);
		if(nReal+nRealSize > length)
		{
			return -1;
		}
		nRealSize += nReal;
	}

	return nRealSize;
}

/*
	DES密钥分配
*/

//生成并发送DES密钥
void DESAllocGener(int sock)
{
	int i, flag;
	char szBuffer[BUFFERSIZE];

	//随机生成DES密钥
	flag = GenerateDESKey(chatkey);
	if(flag)
	{
		printf("Generate DES key successful!\n");
	}
	else
	{
		printf("Generate DES key failed!\n");
		exit(0);
	}

	//接收RSA公钥
	flag = recv(sock, (char*)&publickey, BUFFERSIZE, 0);
	if(!flag)
	{
		printf("Receive RSA public key failed!\n");
		exit(0);
	}

	//加密DES密钥
	long nEncryDESKey[DESKEYLENGTH/2];
	unsigned short* pDesKey = (unsigned short*)chatkey;
	for(i = 0; i < DESKEYLENGTH/2; i++)
	{
		nEncryDESKey[i] = RSAEncry(pDesKey[i], publickey);
	}

	//将加密后的DES密钥发送给服务端
	if(sizeof(long)*DESKEYLENGTH/2 != send(sock, (char*)nEncryDESKey, sizeof(long)*DESKEYLENGTH/2, 0))
	{
		printf("Send DES key failed!\n");
		exit(0);
	}
	else
	{
		printf("Send DES key successful!\n");
	}
}

//生成RSA公私钥对，并解密DES密钥
void DESAllocRecv(int sock)
{
	int i;

	//生成RSA公私钥对
	RSAGetParam();
	publickey = GetPublicKey();

	//将公钥发送给客户端
	if(send(sock, (char*)&publickey, sizeof(publickey), 0) != sizeof(publickey))
	{
		printf("Send RSA public key failed!\n");
		exit(0);
	}
	else
	{
		printf("Send RSA public key successful!\n");
	}

	//接收加密的DES密钥
	long nEncryDESKey[DESKEYLENGTH/2];
	if(recv(sock, (char*)nEncryDESKey, DESKEYLENGTH/2 * sizeof(long), 0) != DESKEYLENGTH/2 * sizeof(long))
	{
		printf("Receive DES key failed!\n");
		exit(0);
	}

	//解密DES密钥
	unsigned short* pDesKey = (unsigned short*)chatkey;
	for(i = 0; i < DESKEYLENGTH/2; i++)
	{
		pDesKey[i] = RSADecry(nEncryDESKey[i]);
	}
}




/*
	RSA
*/

/*
	RSA加解密函数
*/

//初始化RSA参数
void RSAGetParam()
{
	long t;

	//随机生成两个素数
	rsa.p = RandomPrime(16);
	rsa.q = RandomPrime(16);

	//计算模数及相应的f
	rsa.n = rsa.p * rsa.q;
	rsa.f = (rsa.p - 1)*(rsa.q - 1);

	//生成公钥中的e
	do
	{
		rsa.e = rand()%65536;
		rsa.e |= 1;
	}while(Gcd(rsa.e, rsa.f) != 1);

	//生成私钥中的d
	rsa.d = Enclid(rsa.e, rsa.f);

	//计算n结尾连续的比特1
	rsa.s = 0;
	t = rsa.n >> 1;
	while(t)
	{
		rsa.s++;
		t >>= 1;
	}
}

//获取公钥函数
struct PublicKey GetPublicKey()
{
	struct PublicKey key;

	key.nE = rsa.e;
	key.nN = rsa.n;

	return key;
}

//RSA加密函数
long RSAEncry(unsigned short nSource, struct PublicKey publickey)
{
	//将字符串转换为二进制块
	return PowMod(nSource, publickey.nE, publickey.nN);
}

//RSA解密函数
unsigned short RSADecry(long nSource)
{
	long nRes = PowMod(nSource, rsa.d, rsa.n);
	unsigned short* pRes = (unsigned short*)&nRes;
	if(pRes[1] != 0 || pRes[3] != 0 || pRes[2] != 0)
	{
		return 0;
	}

	return pRes[0];
}

/*
	RSA核心函数
*/

//模乘运算
unsigned long MulMod(unsigned long a, unsigned long b, unsigned long n)
{
	return (a*b) %n;
}

//模幂运算
unsigned long PowMod(unsigned long base, unsigned long pow, unsigned long n)
{
	unsigned long a = base, b = pow, c = 1;
	while(b)
	{
		while(!(b & 1))
		{
			b >>= 1;
			a = MulMod(a, a, n);
		}
		b--;
		c = MulMod(a, c, n);
	}

	return c;
}

//拉宾——米勒测试,判别是否为质数
long RabinMillerKnl(unsigned long n)
{
	unsigned long a, q, k, v;
	unsigned int z;
	int i, w;

	//计算出q,k
	q = n - 1;
	k = 0;
	while(!(q & 1))
	{
		++k;
		q >>= 1;
	}

	//随机获取一个数
	a = 2 + rand()%(n - 3);
	v = PowMod(a, q, n);
	if(v == 1)
	{
		return 1;
	}

	//循环检验
	for(i = 0; i < k; i++)
	{
		z = 1;
		for(w = 0; w < i; w++)
		{
			z *= 2;
		}
		if(PowMod(a, z * q, n) == n-1)
		{
			return 1;
		}
	}

	return 0;
}

//重复拉宾——米勒测试
long RabinMiller(unsigned long n, unsigned long loop)
{
	int i;

	for(i = 0; i < loop; i++)
	{
		if(!RabinMillerKnl(n))
		{
			return 0;
		}
	}

	return 1;
}

//质数生成函数
unsigned long RandomPrime(char bits)
{
	unsigned long base;

	do
	{
		base = (unsigned long)1 << (bits - 1);		//保证最高位为1
		base += rand()%base;						//加上一个随机数
		base |= 1;									//保证最低位为1
	}while(!RabinMiller(base, 30));					//进行拉宾——米勒测试30次

	return base;
}

//求最大公约数
unsigned long Gcd(unsigned long p, unsigned long q)
{
	unsigned long a = p>q?p:q;
	unsigned long b = p<q?p:q;
	unsigned long t;

	if(p == q)
	{
		return p;		//若两数相等，最大公约数就是本身
	}
	else
	{
		//辗转相除法
		while(b)
		{
			a = a % b;
			t = a;
			a = b;
			b = t;
		}

		return a;
	}
}

//生成私钥中的d
unsigned long Enclid(unsigned long e, unsigned long t_n)
{
	unsigned long max = 0xffffffffffffffff - t_n;
	unsigned long i = 1, tmp;

	while(1)
	{
		if(((i * t_n) + 1)%e == 0)
		{
			return ((i * t_n)+1) / e;
		}
		i++;
		tmp = (i + 1) * t_n;
		if(tmp > max)
		{
			return 0;
		}
	}

	return 0;
}