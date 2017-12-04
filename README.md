sniffer
=======

Network sniffer for Linux.  Saves SMAC, DMAC, EtherType, SIP, and DIP to
an Sqlite db for analysis.

```
Usage:
  sniffer IFNAME

Options:
  -d       Enable debug messages to log
  -h       This help text
  -l FILE  Log all packets to FILE
```


example
-------

```
$ sudo sniffer eth0
Starting sniffer on iface eth0 ...
sniffer: db open, table created successfully
TCP: 26792  UDP: 4683  ICMP: 7  IGMP: 78  Others: 930  Total: 32490
```

Inspect with `sqlitebrowser /run/sniffer-eth0.db`


build
-----

Supported back-ends are `.txt` log file, sqlite3, and redis.  The
default is redis, since it was easier to implement a flow counter
with that.  To build for sqlite, and get a HUGE db:

    make DB=sqlite

