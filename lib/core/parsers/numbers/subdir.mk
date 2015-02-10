C_SRCS += \
../parsers/numbers/digits.c \
../parsers/numbers/numbers.c 

OBJS += \
./parsers/numbers/digits.o \
./parsers/numbers/numbers.o 

C_DEPS += \
./parsers/numbers/digits.d \
./parsers/numbers/numbers.d 


# Each subdirectory must supply rules for building sources it contributes
parsers/numbers/%.o: ../parsers/numbers/%.c
