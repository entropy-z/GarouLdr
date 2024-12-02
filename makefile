MAKEFLAGS += -s

GPP 	= x86_64-w64-mingw32-g++
NASM    = nasm

INC		= -I include
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
	$(GPP) $(INC) $(CFLAGS) $(SRC) bin/*.o $(OUT)
	python3 ./scripts/extract.py ./bin/GarouLdr.x64.dll ./bin/GarouLdr.x64.bin
	rm bin/*.o

