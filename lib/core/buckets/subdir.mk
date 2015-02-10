OBJS += \
buckets/arrays.o \
buckets/pool.o \
buckets/stacked.o 

C_DEPS += \
./$(DEPDIR)/arrays.d \
./$(DEPDIR)/pool.d \
./$(DEPDIR)/stacked.d 


buckets/%.o: ../buckets/%.c
