OBJS += \
classify/ascii.o 

C_DEPS += \
./$(DEPDIR)/ascii.d 

classify/%.o: ../classify/%.c
