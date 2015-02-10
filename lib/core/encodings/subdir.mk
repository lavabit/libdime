OBJS += \
encodings/base64.o \
encodings/hex.o \
encodings/mappings.o \
encodings/qp.o \
encodings/url.o \
encodings/zbase32.o 

C_DEPS += \
./$(DEPDIR)/base64.d \
./$(DEPDIR)/hex.d \
./$(DEPDIR)/mappings.d \
./$(DEPDIR)/qp.d \
./$(DEPDIR)/url.d \
./$(DEPDIR)/zbase32.d 

encodings/%.o: ../encodings/%.c
