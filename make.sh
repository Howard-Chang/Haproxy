#!/bin/bash
make -j 4 TARGET=linux2628 arch=x86_64 USE_LINUX_TPROXY=1 USE_LINUX_SPLICE=1 USE_LUA=1
