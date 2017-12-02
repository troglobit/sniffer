EXEC   = sniffer

all: $(EXEC)

clean:
	$(RM) $(EXEC)

distclean: clean
	$(RM) *~
