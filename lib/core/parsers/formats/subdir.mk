C_SRCS += \
../parsers/formats/nvp.c 

OBJS += \
./parsers/formats/nvp.o 

C_DEPS += \
./parsers/formats/nvp.d 


# Each subdirectory must supply rules for building sources it contributes
parsers/formats/%.o: ../parsers/formats/%.c
