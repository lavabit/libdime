OBJS += \
log/log.o 

C_DEPS += \
./$(DEPDIR)/log.d 


log/%.o: ../log/%.c
