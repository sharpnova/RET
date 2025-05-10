all: libdisassembler.so libanalyzer.so

libdisassembler.so: disassembler.o lowlevel.o
	gcc -shared -o libdisassembler.so disassembler.o lowlevel.o -lcapstone

disassembler.o: disassembler.c
	gcc -c -fPIC -O2 disassembler.c -o disassembler.o

lowlevel.o: lowlevel.asm
	nasm -f elf64 lowlevel.asm -o lowlevel.o

libanalyzer.so: analyzer.cpp
	g++ -shared -fPIC -O2 -std=c++20 -o libanalyzer.so analyzer.cpp -I/usr/include/python3.11 -lpython3.11 `python3 -m pybind11 --includes`

clean:
	rm -f *.o *.so