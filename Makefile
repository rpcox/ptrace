package  = trace
version  = 1.0
tarname  = $(package)
distdir  = $(tarname)-$(version)
distfile = $(distdir).tar.gz

all clean execve execvp tracee1 tracee2 syscall:
	$(MAKE) -C src $@

dist: $(distfile)
	@echo " *** $(distfile) complete"

$(distfile): $(distdir)
	tar chofz $(distfile) $(distdir)/*
	rm -rf $(distdir)

$(distdir): FORCE
	mkdir -p $(distdir)/src
	cp makefile $(distdir)
	cp LICENSE $(distdir)
	cp README.md $(distdir)
	cp src/*.c $(distdir)/src

check: $(distfile)
	tar xzf $(distfile)
	cd $(distdir) && $(MAKE) all
	cd $(distdir) && $(MAKE) clean
	rm -rf $(distdir)
	@echo " *** $(distfile) check ... OK"

.PHONY: FORCE install

FORCE:
	-rm $(distfile) >/dev/null 2>&1
	-rm -rf $(distdir) >/dev/null 2>&1

install:
	@echo " *** Nothing to install. Execute from src/"


