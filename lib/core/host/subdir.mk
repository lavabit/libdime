OBJS += \
host/files.o \
host/folder.o \
host/host.o \
host/mappings.o \
host/process.o \
host/spool.o 

C_DEPS += \
./$(DEPDIR)/files.d \
./$(DEPDIR)/folder.d \
./$(DEPDIR)/host.d \
./$(DEPDIR)/mappings.d \
./$(DEPDIR)/process.d \
./$(DEPDIR)/spool.d 

host/%.o: ../host/%.c
