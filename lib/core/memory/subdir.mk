OBJS += \
memory/align.o \
memory/bits.o \
memory/memory.o \
memory/secure.o 

C_DEPS += \
./$(DEPDIR)/align.d \
./$(DEPDIR)/bits.d \
./$(DEPDIR)/memory.d \
./$(DEPDIR)/secure.d 

memory/%.o: ../memory/%.c
