
EXEC   = sniffer
OBJS   = sniffer.o csv.o sqlite.o
LDLIBS = -lsqlite3

all: $(EXEC)

$(EXEC): $(OBJS)

clean:
	$(RM) $(EXEC) $(OBJS)

distclean: clean
	$(RM) *~
