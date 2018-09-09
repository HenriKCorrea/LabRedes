#
# Compiler flags
#
CC = gcc
CFLAGS = -Werror -Wextra


#Additional Directories to be included by compiler
#IDIR := -I arp/
#IDIR := $(IDIR) -I Application/DHCPServer/Header/

#Dependencies to be compiled
SRC := $(wildcard ./*.c) #Get all .c files in directory
#SRC := $(SRC) External/pcap/Lib/libpcap.a

#Ouput file name
TARGET = arpspoofing

#
# Release build settings
#
RELDIR = ./
RELTARGET = $(RELDIR)$(TARGET).out
RELCFLAGS = $(CFLAGS) -O3 -DNDEBUG

#
# Debug build settings
#
DBGDIR = ./
DBGTARGET = $(DBGDIR)$(TARGET)_dbg.out
DBGCFLAGS = $(CFLAGS) -g -O0 -DDEBUG

#Optional make commands to be called by the user
.PHONY: clean debug prep_dbg prep_rel release remake runrel rundbg 

# Default build
all: debug release

#
# Debug rules
#
debug: prep_dbg
	$(CC) -o $(DBGTARGET) $(SRC) $(IDIR) $(DBGCFLAGS)
	@#Add the capability of the application use raw sockets without root privileges
	sudo setcap cap_net_raw,cap_net_admin+ep $(DBGTARGET) 

#
# Release rules
#
release: prep_rel
	$(CC) -o $(RELTARGET) $(SRC) $(IDIR) $(RELCFLAGS)
	@#Add the capability of the application use raw sockets without root privileges
	sudo setcap cap_net_raw,cap_net_admin+ep $(RELTARGET) 

#
# Other rules
#
prep_dbg:
	@if test ! -d $(DBGDIR); then mkdir -p $(DBGDIR); fi	#If DBGDIR do not exists, create dir	
	
prep_rel:
	@if test ! -d $(RELDIR); then mkdir -p $(RELDIR); fi	#If RELDIR do not exists, create dir

remake: clean all

clean:
	@if test -e $(DBGTARGET); then rm $(DBGTARGET); fi	#If DBGTARGET file exists, remove it
	@if test -e $(RELTARGET); then rm $(RELTARGET); fi	#If RELTARGET file exists, remove it

runrel:
	sudo $(RELTARGET)
	
rundbg:
	sudo $(DBGTARGET)

