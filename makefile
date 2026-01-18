all: link

link: compile
	gcc -g -m32 -Wall -o myELF myELF.o

compile: clean
	gcc -g -m32 -Wall -c -o myELF.o myELF.c

clean:
	rm -f *.o myELF