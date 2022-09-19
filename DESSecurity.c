/*
	DESSecurity.c
	DES消息加密模块，负责加密和解密消息字符串。
	对外提供两个函数，分别是：加密函数DESEncry()，解密函数DESDecry()。
	DES算法分为三个部分：初始置换、16轮迭代、逆初始置换
	其中16轮迭代运算时DES的核心算法，该部分由四部分运算组成：选择扩展运算、密钥加运算、选择压缩运算、置换运算。
	在16轮迭代运算中，伴随的还有16轮子密钥运算：置换选择、循环左移运算、置换运算。
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "DESSecurity.h"
#include "DESTables.h"

int subkeys[16][48];		//子密钥数组
char textdata[32][64];		//保存数据块的地址

void DESCore(char* szBuffer);							//DES核心算法
void GenerSubkeys(char* key);							//子密钥生成算法
int CheckText(char* szBuffer);							//检测文本长度
void CleanSpace(char* szBuffer);						//去除空格
void CatText(char* szBuffer, int count);				//拼接文本
void GetBits(int num, int* data, int pos, int length);	//获取比特位
int GetBytes(int* source, int pos, int length);			//获取字节值
void ReverSubKeys();									//调整子密钥的顺序

//随机生成DES密钥
int GenerateDESKey(char* key)
{
	//生成密钥长度为64bit，即8字节

	int i, n;
	for(i = 0; i < 8; i++)
	{
		srand(time(NULL));
		n = rand()%3;
		switch(n)
		{
			case 0:
			{
				//数字
				key[i] = (char)rand()%58+48;
				break;
			}
			case 1:
			{
				//大写字母
				key[i] = (char)rand()%91+65;
				break;
			}
			case 2:
			{
				//小写字母
				key[i] = (char)rand()%123+97;
				break;
			}
			default:
			{
				return 0;
				break;
			}
		}
	}
	key[i] = '\0';

	return 1;
}

//DES加密
void DESEncry(char* szBuffer, char key[])
{
	int i;
	int count = 0;		//记录消息分割为数据块的数量

	//检测文本的长度
	count = CheckText(szBuffer);
	
	GenerSubkeys(key);		//生成16个子密钥

	//调用加密算法
	for(i = 0; i < count; i++)
	{
		DESCore(textdata[i]);
	}

	//拼接文本
	CatText(szBuffer, count);
}

//DES解密
void DESDecry(char* szBuffer, char key[])
{
	int i;
	int count = 0;

	//检测文本的长度
	count = CheckText(szBuffer);

	GenerSubkeys(key);		//生成16个子密钥
	ReverSubKeys();			//调整子密钥的顺序
	
	//调用加密算法
	for(i = 0; i < count; i++)
	{
		DESCore(textdata[i]);
	}

	//拼接文本
	CatText(szBuffer, count);
}

//DES核心算法
void DESCore(char* szBuffer)
{
	int i, j;							//循环计数器
	int temprow, tempcol;				//S盒行列记录
	int data[64];						//文本比特位记录
	int dataleft[32], dataright[32];	//等分文本比特位
	int templeft[64], tempright[48];	//扩展文本比特位

	//获取64个数据块
	for(i = 0; i < 8; i++)
	{
		GetBits(szBuffer[i], data, i*8, 8);
	}

	//初始置换
	for(i = 0; i < 64; i++)
	{
		templeft[i] = data[pc_first[i] - 1];
	}
	for(i = 0; i < 32; i++)
	{
		dataleft[i] = templeft[i];
		dataright[i] = templeft[i + 32];
	}

	//16轮迭代运算
	for(i = 0; i < 16; i++)
	{
		//保存本轮右半段
		for(j = 0; j < 32; j++)
		{
			templeft[j] = dataright[j];
		}

		//选择扩展运算
		for(j = 0; j < 48; j++)
		{
			tempright[j] = dataright[des_E[j] - 1];
		}

		//密钥加运算
		for(j = 0; j < 48; j++)
		{
			tempright[j] ^= subkeys[i][j];
		}

		//选择压缩运算
		for(j = 0; j < 8; j++)
		{
			//计算行号
			temprow = tempright[j*6] & 1;
			temprow = temprow << 1;
			temprow = tempright[j*6 + 5] & 1;
			//计算列号
			tempcol = GetBytes(tempright, j*6 + 1, 4);

			GetBits(des_S[j][temprow*16 + tempcol], tempright, j*4, 4);
		}

		//置换运算
		for(j = 0; j < 32; j++)
		{
			dataright[j] = tempright[des_P[j] - 1];
		}

		//与左半段数据异或作为下一轮的右半段，本轮的原始右半段作为下一轮的左半段
		for(j = 0; j < 32; j++)
		{
			dataright[j] ^= dataleft[j];
			dataleft[j] = templeft[j];
		}
	}

	//逆初始置换
	for(i = 0; i < 32; i++)
	{
		templeft[i] = dataright[i];
		templeft[i + 32] = dataleft[i];
	}

	for(i = 0; i < 64; i++)
	{
		data[i] = templeft[pc_last[i] - 1];
	}

	//将加密后的字符串写回缓冲区
	for(i = 0; i < 8; i++)
	{
		szBuffer[i] = GetBytes(data, i*8, 8);
	}
}

/*
	子密钥生成算法由三部分组成：置换选择、循环左移运算、置换运算。
*/

//子密钥生成算法
void GenerSubkeys(char* key)
{
	int i, j, z;
	int templeft, tempright;
	int keydata[64], tempbuff[56];
	int keyleft[28], keyright[28];

	for(i = 0; i < 8; i++)
	{
		GetBits(key[i], keydata, i*8, 8);
	}

	//置换选择
	for(i = 0; i < 28; i++)
	{
		keyleft[i] = keydata[pc_keyleft[i] - 1];
		keyright[i] = keydata[pc_keyright[i] - 1];
	}

	//循环左移运算
	for(i = 0; i < 16; i++)
	{
		for(j = 0; j < moveleft_keynum[i]; j++)
		{
			templeft = keyleft[0];
			tempright = keyright[0];
			for(z = 0; z < 27; z++)
			{
				keyleft[z] = keyleft[z + 1];
				keyright[z] = keyright[z + 1];
			}
			keyleft[27] = templeft;
			keyright[27] = tempright;
		}

		//连接
		for(j = 0; j < 28; j++)
		{
			tempbuff[j] = keyleft[j];
			tempbuff[j + 28] = keyright[j];
		}

		//置换选择
		for(j = 0; j < 48; j++)
		{
			subkeys[i][j] = tempbuff[keychoose[j] - 1];
		}
	}
}

/*
	辅助函数，用于辅助DES运算
*/

//检测文本的长度
int CheckText(char* szBuffer)
{
	int i;
	int count = 0, length = 0;

	//检测长度
	length = strlen(szBuffer);
	if(length == 0)
	{
		return count;
	}

	//对文本进行分割
	while(length != 0)
	{
		if(length/8 != 0)
		{
			for(i = 0; i < 8; i++)
			{
				textdata[count][i] = szBuffer[count*8 + i];
			}
			textdata[count][i] = '\0';
			length -= 8;
			count++;
		}
		else
		{
			if(length == 0)
			{
				break;
			}
			else
			{
				for(i = 0; i < length; i++)
				{
					textdata[count][i] = szBuffer[count*8 + i];
				}
				for(i = length; i < 8; i++)
				{
					textdata[count][i] = 0x20;
				}
				textdata[count][i] = '\0';
				length = 0;
				count++;
			}
		}
	}

	return count;
}

//拼接文本
void CatText(char* szBuffer, int count)
{
	int i, j;

	for(i = 0; i < count; i++)
	{
		for(j = 0; j < 8; j++)
		{
			szBuffer[i*8 + j] = textdata[i][j];
		}
	}
	szBuffer[i*8] = '\0';
	CleanSpace(szBuffer);
}

//去除空格
void CleanSpace(char* szBuffer)
{
	int i;

	for(i = 0; i < strlen(szBuffer); i++)
	{
		if(szBuffer[i] == 0x20)
		{
			szBuffer[i] = '\0';
		}
	}
}

//获取比特位
void GetBits(int num, int* data, int pos, int length)
{
	int i;
	for(i = 0; i < length; i++)
	{
		data[pos + (length - i - 1)] = (num >> i) & 1;
	}
}

//获取字节值
int GetBytes(int* source, int pos, int length)
{
	int i, result = 0;

	for(i = 0; i < length; i++)
	{
		result = result | source[pos + i];
		if(i != length - 1)
		{
			result = result << 1;
		}
	}

	return result;
}

//调整子密钥的顺序
void ReverSubKeys()
{
	int i, j;
	int temp[16][48];

	for(i = 15; i >= 0; i--)
	{
		for(j = 0; j < 48; j++)
		{
			temp[i][j] = subkeys[15-i][j];
		}
	}
	for(i = 0; i < 16; i++)
	{
		for(j = 0; j < 48; j++)
		{
			subkeys[i][j] = temp[i][j];
		}
	}
}