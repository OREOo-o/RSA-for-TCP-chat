/*
	Chat.c
	该文件是程序的主文件，用于完成聊天功能的选择和调用。
	聊天程序分为四个模块：主模块、TCP通信模块、DES信息加密模块、RSA密钥分配模块。
		主模块：即控制端，用于根据不同的情况调用不同的功能以实现不同的需求。
		TCP通信模块：即通信模块，负责聊天程序的消息传递、接收等通信需求。
		DES信息加密模块：即消息安全模块，负责聊天程序中消息的安全传输。
		RSA密钥分配模块：即密钥安全模块，负责聊天程序中消息加密密钥的安全传输。
*/

#include <stdio.h>
#include <string.h>
#include "Chat.h"
#include "TCPCommun.h"

char ChooseCorS();	//选择身份

int main(int argc, char* argv[])
{
	char id;				//身份标记
	char serveraddr[20];	//服务器IP地址

	//选择执行的身份
	id = ChooseCorS();

	//启动服务
	switch(id)
	{
		case 'c':
		{
			//获取服务器地址
			printf("Please input the server address:\n");
			scanf("%s", serveraddr);
			if(strlen(serveraddr) <= 0 || strlen(serveraddr) > 16)
			{
				printf("sorry,the server address input error!");
			}
			else
			{
				//建立连接
				ClientToServer(serveraddr);
			}

			break;
		}
		case 's':
		{
			//监听连接
			ServerToClient();

			break;
		}
		default:
		{
			printf("sorry,the Id has an error!");
			break;
		}
	}

	return 0;
}

//选择执行的身份
char ChooseCorS()
{
	char id;
	char input[10];

	printf("please select:Client or Server?\n");
	scanf("%s", input);

	//输入检查
	if(strcmp(input, "c") && strcmp(input, "C") && strcmp(input, "client") && strcmp(input, "Client"))
	{
		if(strcmp(input, "s") && strcmp(input, "S") && strcmp(input, "server") && strcmp(input, "Server"))
		{
			printf("Input error!");
			id = 'e';
		}
		else
		{
			id = 's';
		}
	}
	else
	{
		id = 'c';
	}

	return id;
}