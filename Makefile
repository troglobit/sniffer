EXEC   = sniffer
LDLIBS = -lsqlite3

all: $(EXEC)

clean:
	$(RM) $(EXEC)

distclean: clean
	$(RM) *~
