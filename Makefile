all: netfilter-test

netfilter-test: main.o
	gcc -o netfilter-test main.o -lnetfilter_queue

main.o: main.c