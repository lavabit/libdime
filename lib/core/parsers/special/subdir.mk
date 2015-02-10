C_SRCS += \
../parsers/special/bracket.c 

OBJS += \
./parsers/special/bracket.o 

C_DEPS += \
./parsers/special/bracket.d 


# Each subdirectory must supply rules for building sources it contributes
parsers/special/%.o: ../parsers/special/%.c
