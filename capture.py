#!/usr/bin/env python2

import os
import glob
import socket
from struct import pack
import sys
import json


def capture_process(pid):
  proc = '/proc/%d' % pid

  if not os.path.exists(proc):
    return

  comm = open('/proc/%d/comm' % pid, 'r').read().rstrip('\n')

  uid = None
  f = open('/proc/%d/status' % pid, 'r')
  for line in f.readlines():
    if line.startswith('Uid:'):
      elms = line.split()
      uid = int(elms[1])
      break

  assert(uid is not None)

  selinux = 'none'
  if os.path.exists('/proc/%d/attr/current' % pid):
    selinux = open('/proc/%d/attr/current' % pid, 'r').read().rstrip('\n').split('\x00')[0]

  inodes = []

  for fd in glob.iglob(proc + '/fd/[0-9]*'):
    name = os.readlink(fd)
    if name.startswith('socket:['):
      inodes.append({'ino': name[8:-1], 'extra': 'socket'})
    elif name.startswith('pipe:['):
      inodes.append({'ino': name[6:-1], 'extra': 'pipe'})

  p = {
    'cmd': comm,
    'uid': uid,
    'pid': pid,
    'selinux': selinux,
    'inodes': inodes,
  }

  return p



def capture_procs():
  procs = {}

  SELFPROC = '/proc/%d' % (os.getpid())

  for proc in glob.iglob('/proc/[0-9]*'):
    if proc == SELFPROC:
      continue

    pid = int(proc.split('/')[-1])
    p = capture_process(pid)

    # might happen if an ephemeral process has died between the iglob and its processing
    # just continue then
    if not p:
      continue

    assert(p['pid'] == pid)
    assert(p['pid'] not in procs)
    procs[p['pid']] = p

  return procs


'''
/proc/net/udp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1171: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 16847 2 ffff98a3a8b18c00 0
/proc/net/udp6
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1522: 00000000000000000000000000000000:1194 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 19547 2 ffff98a39a06ef80 0
/proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 16848 1 ffff98a3a9677000 100 0 0 10 0
/proc/net/tcp6
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:22B8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1870100 1 ffff98a3a942e600 100 0 0 10 0
/proc/net/raw
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   6: 0101007F:0006 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1870533 2 ffff98a38f5430c0 0
/proc/net/raw6
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   58: 00000000000000000000000000000000:003A 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   100        0 15881 2 ffff98a3a5c0a400 0
/proc/net/packet
sk       RefCnt Type Proto  Iface R Rmem   User   Inode
ffff98a3a6419800 3      3    88cc   2     1 0      100    15804
/proc/net/sctp/eps
 ENDPT     SOCK   STY SST HBKT LPORT   UID INODE LADDRS
ffff98a3a73a4300 ffff98a2843779c0 2   10  22   8888      0 1870579 0.0.0.0
/proc/net/sctp/assocs
 ASSOC     SOCK   STY SST ST HBKT ASSOC-ID TX_QUEUE RX_QUEUE UID INODE LPORT RPORT LADDRS <-> RADDRS HBINT INS OUTS MAXRT T1X T2X RTXC wmema wmemq sndbuf rcvbuf
ffff98a3286d5800 ffff98a284374000 2   1   3  0       2        0        0       0 1870580 8888  40384  127.0.0.1 149.202.60.45 <-> *127.0.0.1 149.202.60.45 	    7500    10    10   10    0    0        0        1        0   212992   212992
/proc/net/unix
Num       RefCount Protocol Flags    Type St Inode Path
ffff9053f5b98400: 00000002 00000000 00010000 0001 01 33783 /var/run/mcelog-client
ffff9053f7976000: 00000002 00000000 00000000 0002 01 33623
'''

def decode_addr4(data):
  (addr, port) = map(lambda x: int(x, 16), data.split(':'))
  packed_addr = pack('I', addr)
  return (socket.inet_ntop(socket.AF_INET, packed_addr), port)

def decode_addr6(data):
  (addr, port) = map(lambda x: int(x, 16), data.split(':'))
  packed_addr = pack('Q', addr>>64) + (pack('Q', addr&0xffffffffffffffff))
  return (socket.inet_ntop(socket.AF_INET6, packed_addr), port)

def decode_port(data):
  port = int(data.split(':')[1], 16)
  return port

NET_TABLES = {
  'udp': {'local': 1, 'remote': 2, 'inode': 9, 'n_elms': 13, 'decode': decode_addr4},
  'udp6': {'local': 1, 'remote': 2, 'inode': 9, 'n_elms': 13, 'decode': decode_addr6},
  'tcp': {'local': 1, 'remote': 2, 'inode': 9, 'n_elms': 12, 'decode': decode_addr4},
  'tcp6': {'local': 1, 'remote': 2, 'inode': 9, 'n_elms': 12, 'decode': decode_addr6},
  'raw': {'local': 1, 'remote': 2, 'inode': 9, 'n_elms': 13, 'decode': decode_port},
  'raw6': {'local': 1, 'remote': 2, 'inode': 9, 'n_elms': 13, 'decode': decode_port},
  'packet': {'inode': 8, 'n_elms': 9},
}

def capture_unix():
  with open('/proc/net/unix', 'r') as f:
    header = f.readline()
    for line in f.readlines():
      elms = line.split()
      assert(len(elms) >= 7)

      inode = int(elms[6])
      if len(elms) == 8:
        path = elms[7]
      else:
        path = None

      yield {'type': 'unix', 'inode': inode, 'path': path}

def capture_sctp_assocs():
  SCTP_ASSOCS = '/proc/net/sctp/assocs'
  if not os.path.exists(SCTP_ASSOCS):
    return

  with open(SCTP_ASSOCS, 'r') as f:
    header = f.readline()
    for line in f.readlines():
      elms = line.split()
      assert(len(elms) >= 27)

      (l_elms, r_elms) = line.split('<->')
      l_elms = l_elms.split()
      r_elms = r_elms.split()

      inode = int(l_elms[10])
      l_port = int(l_elms[11])
      r_port = int(l_elms[12])

      l_addrs = l_elms[13:]

      yield {'type': 'sctp', 'inode': inode, 'local': (l_addrs, l_port), 'remote': (r_port,)}


def capture_net_table(name):
  assert(name in NET_TABLES)

  ctes = NET_TABLES[name]
  assert('n_elms' in ctes)
  assert('inode' in ctes)
  assert(('local' in ctes and 'remote' in ctes and 'decode' in ctes) or ('local' not in ctes and 'remote' not in ctes and 'decode' not in ctes))

  with open('/proc/net/%s' % name, 'r') as f:
    header = f.readline()
    for line in f.readlines():
      elms = line.split()

      if len(elms) < ctes['n_elms']:
        print('line %r does not contain the correct number of elements (%d)' % (line, ctes['n_elms']))
      assert(len(elms) >= ctes['n_elms'])

      inode = int(elms[ctes['inode']], 10)

      if 'local' in ctes:
        local = ctes['decode'](elms[ctes['local']])
        remote = ctes['decode'](elms[ctes['remote']])
        yield {'type': name, 'local': local, 'remote': remote, 'inode': inode}
      else:
        yield {'type': name, 'inode': inode}
      
def capture_net():
  inodes = {}

  for name in ('udp', 'udp6', 'tcp', 'tcp6', 'raw', 'raw6', 'packet'):
    for i in capture_net_table(name):
      ino = i['inode']
      del i['inode']
      assert(ino not in inodes)
      inodes[ino] = i

  for gen in (capture_sctp_assocs, capture_unix):
    for i in gen():
      ino = i['inode']
      del i['inode']
      assert(ino not in inodes)
      inodes[ino] = i

  return inodes

procs = capture_procs()
net = capture_net()

print(json.dumps({'processes': procs, 'net': net}))
