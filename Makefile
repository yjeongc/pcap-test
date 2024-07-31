#Makefile

all : Pcap_programming

Pcap_programming : Pcap_programming.o
		gcc -o Pcap_programming Pcap_programmingl.o -lpcap

Pcap_programming : Pcap_programming.c
		gcc -c -o Pcap_programming.o Pcap_programming.c -lpcap

clean:
	rm -f *.o
	rm -f Pcap_programming