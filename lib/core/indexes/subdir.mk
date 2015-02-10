OBJS += \
indexes/cursors.o \
indexes/hashed.o \
indexes/inx.o \
indexes/linked.o 

C_DEPS += \
./$(DEPDIR)/cursors.d \
./$(DEPDIR)/hashed.d \
./$(DEPDIR)/inx.d \
./$(DEPDIR)/linked.d 

indexes/%.o: ../indexes/%.c
