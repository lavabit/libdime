OBJS += \
hash/adler.o \
hash/crc.o \
hash/fletcher.o \
hash/murmur.o 

C_DEPS += \
./$(DEPDIR)/adler.d \
./$(DEPDIR)/crc.d \
./$(DEPDIR)/fletcher.d \
./$(DEPDIR)/murmur.d 

hash/%.o: ../hash/%.c
