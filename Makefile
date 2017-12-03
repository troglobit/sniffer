EXEC   = sniffer
LDLIBS = -lsqlite3

all: $(EXEC)

$(EXEC): sniffer.o sqlite.o

clean:
	$(RM) $(EXEC)

distclean: clean
	$(RM) *~
