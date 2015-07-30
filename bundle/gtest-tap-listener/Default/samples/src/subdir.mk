################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../samples/src/gtest_main.cc \
../samples/src/gtest_testHelloWorld.cc 

OBJS += \
./samples/src/gtest_main.o \
./samples/src/gtest_testHelloWorld.o 

CC_DEPS += \
./samples/src/gtest_main.d \
./samples/src/gtest_testHelloWorld.d 


# Each subdirectory must supply rules for building sources it contributes
samples/src/%.o: ../samples/src/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I/opt/googletest/include -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


