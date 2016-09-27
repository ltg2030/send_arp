#ifndef _MyARPSend

#define _MyARPSend

#include <string>
#include <stdint.h>

using namespace std;

class MyARPSend{

private:
    string victim_ip;
    string victim_mac;
    string gateway_ip;
    string gateway_mac;
    string my_ip;
    string my_mac;

    void set_arp_spoofing_attack();

    void get_my_ip();
    void get_my_mac();
    void get_gateway_ip();

    void get_victim_mac();
    void get_gateway_mac();

    void convert_ip_to_MAC(string &, string &);
    void sendpacket(uint8_t *buf, int size);

public:
    MyARPSend();
    MyARPSend(string &);

    void send_request_packet();
    void send_spoof_packet();
};

#endif
