MAKEFLAGS += -s

GCC 	= x86_64-w64-mingw32-gcc
NASM    = nasm

INC		= -I Include
SRC     = $(wildcard src/*.c)

CFLAGS =  -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS += -s -ffunction-sections -Iagent/include -falign-jumps=1 -w -m64 
CFLAGS += -falign-labels=1 -fPIC -Wl,-Tscripts/linker.ld
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS += -masm=intel -fpermissive -mrdrnd

OUT		= -o bin/GarouLdr.x64.dll

rdll:
	nasm -f win64 src/asm/garou.s -o bin/garou.o
	$(GCC) $(INC) $(CFLAGS) $(SRC) bin/*.o $(OUT)
	rm bin/*.o

hasher:
	x86_64-w64-mingw32-gcc -w -s .\scripts\Hasher.c -o .\scripts\Hasher.exe
