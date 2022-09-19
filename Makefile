# 生成Chat
Chat:DESSecurity.o DESTables.o TCPCommun.o Chat.o
	gcc -o Chat DESSecurity.o DESTables.o TCPCommun.o Chat.o

# 生成DESSecurity.o
DESSecurity.o:DESSecurity.c DESSecurity.h
	gcc -c -o DESSecurity.o DESSecurity.c

# 生成DESTables.o
DESTables.o:DESTables.c DESTables.h
	gcc -c -o DESTables.o DESTables.c

# 生成RSASecurity.o
#RSASecurity.o:RSASecurity.c RSASecurity.h
#	gcc -c -o RSASecurity.o RSASecurity.c

# 生成TCPCommun.o
TCPCommun.o:TCPCommun.c TCPCommun.h
	gcc -c -o TCPCommun.o TCPCommun.c

# 生成Chat.o
Chat.o:Chat.c Chat.h
	gcc -c -o Chat.o Chat.c

# 清楚规则
clean:
	rm -f TCPCommun.o DESSecurity.o DESTables.o Chat.o Chat