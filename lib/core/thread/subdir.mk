OBJS += \
thread/keys.o \
thread/mutex.o \
thread/rwlock.o \
thread/thread.o 

C_DEPS += \
./$(DEPDIR)/keys.d \
./$(DEPDIR)/mutex.d \
./$(DEPDIR)/rwlock.d \
./$(DEPDIR)/thread.d 

thread/%.o: ../thread/%.c
