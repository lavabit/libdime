OBJS += \
parsers/case.o \
parsers/line.o \
parsers/time.o \
parsers/token.o \
parsers/trim.o 

C_DEPS += \
./$(DEPDIR)/case.d \
./$(DEPDIR)/line.d \
./$(DEPDIR)/time.d \
./$(DEPDIR)/token.d \
./$(DEPDIR)/trim.d 

parsers/%.o: ../parsers/%.c
