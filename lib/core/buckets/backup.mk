################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../buckets/arrays.c \
../buckets/pool.c \
../buckets/stacked.c 

OBJS += \
./buckets/arrays.o \
./buckets/pool.o \
./buckets/stacked.o 

C_DEPS += \
./buckets/arrays.d \
./buckets/pool.d \
./buckets/stacked.d 


# Each subdirectory must supply rules for building sources it contributes
buckets/%.o: ../buckets/%.c
