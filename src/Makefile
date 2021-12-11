cc     = gcc
cflags = -g -O0 -Wall -rdynamic -std=c11

all: syscall execve execvp tracee1 tracee2
	@echo
	@echo " *** usage: execve PROGRAM [OPTIONS]"
	@echo " *** usage: execvp PROGRAM [OPTIONS]"
	@echo " *** usage: syscall PROGRAM [OPTIONS]"
	@echo

execve: execve.c
	$(cc) $(cflags) $+ -o $@

execvp: execvp.c
	$(cc) $(cflags) $+ -o $@

syscall: syscall.c
	$(cc) $(cflags) $+ -o $@

tracee1: tracee1.c
	$(cc) $(cflags) $+ -o $@

tracee2: tracee2.c
	$(cc) $(cflags) $+ -o $@

.PHONY : clean
clean:
	-rm -f execve execvp syscall tracee1 tracee2
	-rm -f *.o

