extern int pc_first[64];		//初始置换表
extern int pc_last[64];			//逆初始置换表

extern int des_E[48];			//选择扩展E盒
extern int des_P[32];			//置换运算P盒
extern int des_S[8][64];		//选择压缩S盒

//等分密钥
extern int pc_keyleft[28];
extern int pc_keyright[28];
extern int moveleft_keynum[16];	//密钥循环左移运算
extern int keychoose[48];		//置换选择