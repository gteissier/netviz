# netviz

Capture /proc infos and visualize network flows between processes and machines.

The objective is to understand and visualize network flows between a group of Linux machines. These flows may be between machines, or inside a machine e.g. a connection between Apache and mysql database. A flow will be visualized if it spans machines of the group. Note in particular:

* Connections to the outside of the group are not displayed. For examples, an heavy loaded web server will display connection to the database on the loopback, but not any of the public Internet connected clients, as they will likely be not in the group of study


The process is split in two steps:

* **capture**: a snapshot of network and process information is taken on several Linux machines. [capture.py](capture.py) serves this purpose, and generates a json file containing the required information. These snapshots will be stitched, and need to be gathered.
* **stitch**: snapshots are loaded and stitched whenever possible. Flows between processes will generated as long as this flow starts and ends on machines of the group. Machines associated with a flow may be the same machine, in this case, it indicates a loopback flow.
* **visualize**: simply use dot on generated graph file.

Several network sockets are captured:

* tcp, tcp6, udp and udp6, sctp: they form usual network transport channels
* raw, raw6 and packet: they are sometimes used, and it is important to spot it as an ingress to the system, reachable via packets

## capture

```
$ python3 capture.py > snapshot.json
```

Next, retrieve the snapshot.json file and process it with [stitch.py](stitch.py).

### Process related infos

They are collected:

* `/proc/pid/comm`: the name of the process
* `/proc/pid/fd/[0-9]*`: the opened file descriptors, which will yield inodes, and allows to trace sockets back to processes
* `/proc/pid/status`: the uid of the process
* `/proc/pid/attr/current`: the security context of the process, which apparently works for SELinux or apparmor

### Network sockets

They are collected in:

* `/proc/net/tcp`: the list of IPv4 TCP sockets
* `/proc/net/tcp6`: the list of IPv6 TCP sockets
* `/proc/net/udp`: the list of IPv4 UDP sockets
* `/proc/net/udp6`: the list of IPv6 UDP sockets
* `/proc/net/raw`: the list of IPv4 RAW sockets
* `/proc/net/raw:6`: the list of IPv6 RAW sockets
* `/proc/net/packet`: the list of PACKET sockets
* `/proc/net/sctp/assocs`: the list of IPv4 SCTP associations

## stitch

```
$ python3 stitch.py --log debug ./vps.json > vps.dot
```

## visualize

```
dot -Tsvg < vps.dot > vps.svg
```

