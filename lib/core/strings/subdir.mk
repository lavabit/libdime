OBJS += \
strings/allocation.o \
strings/data.o \
strings/info.o \
strings/length.o \
strings/multi.o \
strings/nuller.o \
strings/opts.o \
strings/print.o \
strings/replace.o \
strings/shortcuts.o \
strings/validate.o 

C_DEPS += \
./$(DEPDIR)/allocation.d \
./$(DEPDIR)/data.d \
./$(DEPDIR)/info.d \
./$(DEPDIR)/length.d \
./$(DEPDIR)/multi.d \
./$(DEPDIR)/nuller.d \
./$(DEPDIR)/opts.d \
./$(DEPDIR)/print.d \
./$(DEPDIR)/replace.d \
./$(DEPDIR)/shortcuts.d \
./$(DEPDIR)/validate.d 

strings/%.o: ../strings/%.c
