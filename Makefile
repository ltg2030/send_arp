all: main.cpp
	g++ main.cpp -o pcap_test -lpcap

clean:
	rm -f pcap_test
