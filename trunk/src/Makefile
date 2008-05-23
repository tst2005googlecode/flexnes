CC = gcc
CPP = g++
CFLAGS =  -Wall -Werror -g 
LDFLAGS= -lboost_program_options -lnetfilter_queue_libipq -lnetfilter_queue 
INCLUDES = 

OBJS = flexNES.o fnOptions.o fnState.o fnCore.o fnPacket.o  /usr/lib64/libnet.a

.cpp.o:
	$(CPP) -c $(INCLUDES) $(CFLAGS) $<

.c.o:
	$(CC) -c $(INCLUDES) $(CFLAGS) $<

all: .depend $(OBJS)
	$(CPP) $(LDFLAGS) -o flexNES $(OBJS) 

depend: *.cpp
	rm -f .depend
	$(CPP) -M $(INCLUDES) $(CFLAGS) *.cpp > .depend

clean:
	rm -f *.o core .depend*
	
# Include the dependency information from make depend
ifeq (.depend,$(wildcard .depend))
include .depend
endif
