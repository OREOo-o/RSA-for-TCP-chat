#ifdef __DESSECURITY_H__
#define __DESSECURITY_H__

extern int GenerateDESKey(char* key);					//随机生成DES密钥
extern void DESEncry(char* szBuffer, char key[]);		//消息加密
extern void DESDecry(char* szBuffer, char key[]);		//消息解密

#endif