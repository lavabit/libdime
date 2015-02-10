CC	= gcc
CFLAGS	= -DMAGMA_PEDANTIC -D_REENTRANT -D_GNU_SOURCE -DFORTIFY_SOURCE=2 -DHAVE_NS_TYPE -D_LARGEFILE64_SOURCE -O0 -g3 -rdynamic -Wall -Werror -c -fmessage-length=0 -std=gnu99 -fPIC -MMD -MP
INC	= -I ../../include/core
OBJDIR  = .objs
DEPDIR  = .deps

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
type.c \
other.c \
global.c

OBJS += \
type.o \
other.o \
global.o

C_DEPS += \
type.d \
other.d \
global.d


# Each subdirectory must supply rules for building sources it contributes
%.o: %.c
	@test -d $(OBJDIR) || mkdir $(OBJDIR)
	@test -d $(DEPDIR) || mkdir $(DEPDIR)
	$(CC) $(CFLAGS) $(INC) -MF"$(@F:%.o=$(DEPDIR)/%.d)" -MT"$(@F:%.o=$(DEPDIR)/%.d)" -o$(OBJDIR)/"$(@F)" "$<"
