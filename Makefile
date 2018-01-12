
all:
	cc -g -c cJSON.c
	cc -g -c ifinfo.c
	cc -g -o ifinfo ifinfo.o cJSON.o
	
