CC     = g++
CFLAGS = -g -Wall
OBJS   = airodump-yb.o
TARGET = airodump-yb

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap -lpthread
	rm *.o

main.o: header.h function.h airodump-yb.cpp

clean:
	rm -rf *.o $(TARGET)
