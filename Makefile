all: sender receiver md5

sender: sender.c func_util.c
	gcc -g -w sender.c func_util.c -lpcap -lpthread -o sender

receiver: receiver.c func_util.c
	gcc -g -w receiver.c func_util.c -lpcap -lpthread -o receiver
	
md5: md5.c
	gcc -g -w md5.c -lssl -lcrypto -o md5

clean:
	rm -rf sender receiver md5
