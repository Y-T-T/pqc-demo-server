#ifndef FPGA_UART_H
#define FPGA_UART_H

// #define BAUDRATE B115200
// #define PYNQ_PORTNAME "/dev/ttyUSB0"

#include <base/types.h>

size_t fpga_kyber768(u8 *ct, u8 *ss, const u8 *pk);

#endif