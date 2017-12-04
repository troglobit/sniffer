DB    ?= redis

EXEC   = sniffer
OBJS   = sniffer.o csv.o $(DB).o

ifeq ($(DB),sqlite)
LDLIBS = -lsqlite3
else
LDLIBS = -lhiredis
endif

all: $(EXEC)

$(EXEC): $(OBJS)

clean:
	$(RM) $(EXEC) $(OBJS)

distclean: clean
	$(RM) *~
