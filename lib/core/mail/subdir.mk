OBJS += \
mail/counters.o \
mail/headers.o \
mail/mime.o 

C_DEPS += \
./$(DEPDIR)/counters.d \
./$(DEPDIR)/headers.d \
./$(DEPDIR)/mime.d 

mail/%.o: ../mail/%.c
