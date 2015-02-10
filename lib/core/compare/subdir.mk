OBJS += \
compare/ends.o \
compare/equal.o \
compare/search.o \
compare/starts.o 

C_DEPS += \
./$(DEPDIR)/ends.d \
./$(DEPDIR)/equal.d \
./$(DEPDIR)/search.d \
./$(DEPDIR)/starts.d 

compare/%.o: ../compare/%.c
