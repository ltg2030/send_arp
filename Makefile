OBJECTS = MyMAC.o MyETHER.o MyIPV4.o MyARP.o MyARPSend.o main.o

all: $(OBJECTS)
	g++ -o MyARPSpoofing $(OBJECTS) -lpcap
	rm $(OBJECTS)

MyMAC.o: MyMAC.cpp MyMAC.h
	g++ -c MyMAC.cpp

MyETHER.o: MyETHER.cpp MyETHER.h
	g++ -c MyETHER.cpp

MyIPV4.o: MyIPV4.cpp MyIPV4.h
	g++ -c MyIPV4.cpp

MyARP.o: MyARP.cpp MyARP.h
	g++ -c MyARP.cpp

MyARPSend.o: MyARPSend.cpp MyARPSend.h
	g++ -c MyARPSend.cpp

main.o: main.cpp
	g++ -c main.cpp

clean:
	rm MyARPSpoofing
