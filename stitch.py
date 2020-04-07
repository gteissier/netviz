#!/usr/bin/env python3

import json
import logging
import os.path
import html

def gen_connected(a_rows, b_rows, applies_to_self=False):
  for i in range(len(a_rows)):
    (ino_a, a) = a_rows[i]

    if applies_to_self:
      for j in range(i+1, len(b_rows)):
        (ino_b, b) = b_rows[j]
        if b['remote'] == a['local'] and a['remote'] == b['local']:
          yield (i, j)
    else:
      for j in range(len(b_rows)):
        (ino_b, b) = b_rows[j]
        if b['remote'] == a['local'] and a['remote'] == b['local']:
          yield (i, j)

class Machine:
  def __init__(self, fname, name=None):
    if name is not None:
      self.name = name
    else:
      self.name = os.path.basename(fname).replace('.json', '').replace('.js', '')

    logging.info(f'Loading file {fname}, nicknamed {self.name}')

    with open(fname, 'r') as f:
      r = json.load(f)
      self.processes = r['processes']
      self.net = r['net']

    if type(self.net) != dict:
      raise ValueError(f'Wrong type for attribute net: got {type(self.net)}, expected dict')
    if type(self.processes) != dict:
      raise ValueError(f'Wrong type for attribute processes: got {type(self.processes)}, expected dict')

    for ino, extra in self.net.items():
      if 'type' not in extra:
        raise ValueError(f'Missing attribute type in {extra}')
      if extra['type'] not in ('tcp', 'tcp6', 'udp', 'udp6', 'raw', 'raw6', 'packet', 'sctp', 'unix'):
        raise ValueError(f"Invalid type {extra['type']} in {extra}")

      if extra['type'] in ('tcp', 'tcp6', 'udp', 'udp6', 'sctp'):
        if 'remote' not in extra:
          raise ValueError(f'Missing attribute remote in {extra}')
        if type(extra['remote']) != list:
          raise ValueError(f"Wrong type for attribute remote: got {type(extra['remote'])}, expected list")

        # Tag listeners
        # raw-like sockets
        if extra['type'] in ('raw', 'raw6', 'packet'):
          extra['listener'] = True
          self.net[ino] = extra
          logging.debug(f'Tagged a listener {extra}')

        # and unbound normal sockets
        if extra['type'] in ('tcp', 'tcp6', 'udp', 'udp6') and \
          extra['remote'] == ['0.0.0.0', 0] or extra['remote'] == ['::', 0]:
          extra['listener'] = True
          self.net[ino] = extra
          logging.debug(f'Tagged a listener {extra}')

    for (pid, process) in self.processes.items():
      if type(process) != dict:
        raise ValueError(f'Wrong type: got {type(process)}, expected dict')
      if 'inodes' not in process:
        raise ValueError(f'Missing attribute inodes in {process}')
      if 'cmd' not in process:
        raise ValueError(f'Missing attribute cmd in {process}')

    logging.debug(f'Loaded {len(self.processes)} processes')
    logging.debug(f'Loaded {len(self.net)} network sockets')

    self.tcp_rows = [x for x in self.gen_inodes_by_type('tcp')]
    logging.debug(f'Loaded {len(self.tcp_rows)} TCP sockets')
    self.tcp6_rows = [x for x in self.gen_inodes_by_type('tcp6')]
    logging.debug(f'Loaded {len(self.tcp6_rows)} TCP6 sockets')
    self.udp_rows = [x for x in self.gen_inodes_by_type('udp')]
    logging.debug(f'Loaded {len(self.udp_rows)} UDP sockets')
    self.udp6_rows = [x for x in self.gen_inodes_by_type('udp6')]
    logging.debug(f'Loaded {len(self.udp6_rows)} UDP6 sockets')

    self.cluster_rank = None

  def gen_inodes_by_type(self, nettype):
    for ino, extra in self.net.items():
      if nettype == extra['type']:
        yield (ino, extra)

  def gen_processes_by_ino(self, ino):
    for (pid, process) in self.processes.items():
      for inode in process['inodes']:
        if inode['ino'] == ino:
          yield (pid, process)
          # a process might have the same inode
          # opened multiple times
          # we only yield this process once
          break

  def get_process(self, ino):
    matchings = [p for p in self.gen_processes_by_ino(ino)]
    if not matchings: return

    # it may happen to have multple processes using the same inode, e.g. unix fd passing
    # if so, return one of the process to have link with other machines
    # anyway, communicating this way is not reliable, so cannot be accounted for a real
    # transport channel

    return matchings[0][1]

  def get_process_by_pid(self, pid):
    if type(pid) == int:
      pid = '%d' % pid

    return self.processes[pid]

  def get_process_label(self, pid):
    process = self.get_process_by_pid(pid)

    r = '<<table border="1" cellborder="0" cellspacing="1"><tr><td bgcolor="gray"><b>%s</b></td></tr>' % html.escape(process['cmd'])
    r += '<tr><td bgcolor="lightgray">pid %d</td></tr>' % process['pid']
    if process['uid'] == 0:
      r += '<tr><td><font color="red"><b>uid %d</b></font></td></tr>' % process['uid']
    else:
      r += '<tr><td>uid %d</td></tr>' % process['uid']
    if 'unconfined' in process['selinux']:
      r += '<tr><td><font color="red"><b>%s</b></font></td></tr>' % html.escape(process['selinux'])
    else:
      r += '<tr><td>%s</td></tr>' % html.escape(process['selinux'])
    r += '</table>>'

    return r

    
  def stitch_with(self, other):
    for rows in ('tcp_rows', 'tcp6_rows', 'udp_rows', 'udp6_rows'):
      self_rows = getattr(self, rows)
      other_rows = getattr(other, rows)

      applies_to_self = (self == other)

      for (i,j) in gen_connected(self_rows, other_rows, applies_to_self):
        (ino_i, extra_i) = self_rows[i]
        (ino_j, extra_j) = other_rows[j]

        p_i = self.get_process(ino_i)
        p_j = other.get_process(ino_j)

        label = '<<table border="0" cellborder="0" cellspacing="1" bgcolor="lightgray">'
        label += '<tr border="0"><td align="right"><b>%s</b></td></tr>' % (rows.replace('_rows', ''))
        flow_id = '%s:%d <-> %s:%d' % (extra_i['local'][0], extra_i['local'][1],
          extra_j['local'][0], extra_j['local'][1])
        label += '<tr border="0"><td>%s</td></tr>' % html.escape(flow_id)
        label += '</table>>'

        if self != other or \
          (self == other and p_i != p_j):
          yield (p_i, p_j, label)


def stitch(captures):
  links = set()

  for i in range(len(captures)):
    for j in range(i, len(captures)):
      logging.info(f'Stitching {captures[i].name} to {captures[j].name}')

      for (p_i, p_j, label) in captures[i].stitch_with(captures[j]):
        logging.debug(f"Linking {captures[i].name}:{p_i['cmd']} with {captures[j].name}:{p_j['cmd']}")
        links.add((i, p_i['pid'], j, p_j['pid'], label))

  return links


def write_dot_header(f):
  f.write('graph {\n  splines="line";\nrankdir=LR;\n')

def write_dot_footer(f):
  f.write('}\n')

if __name__ == '__main__':
  import argparse
  import sys

  parser = argparse.ArgumentParser(description='Stitch JSON network captures.')
  parser.add_argument('files', metavar='F', type=str, nargs='+',
    help='A file to process and to stitch with other files')
  parser.add_argument('--output', dest='output', type=str, default='-',
    help='An output file, defaults to stdout')
  parser.add_argument('--log', dest='loglevel', choices=('debug', 'warn', 'info'))
  parser.set_defaults(verbose=False, loglevel='info')

  args = parser.parse_args()

  level = getattr(logging, args.loglevel.upper(), None)
  if type(level) != int:
    raise ValueError('Invalid log level: %s' % (args.loglevel))
  logging.basicConfig(level=level, stream=sys.stderr)

  if args.output == '-':
    outfile = sys.stdout
  else:
    outfile = open(args.output, 'w')


  # Load json snapshots
  captures = []
  for file in args.files:
    if args.verbose:
      logging.info()
    m = Machine(file)
    m.capture_rank = len(captures)
    captures.append(m)

  # Stitch snapshots, even stitch each snapshot with itself
  links = stitch(captures)

  # Generate output
  write_dot_header(outfile)

  machines = {}

  for (i, p_i, j, p_j, label) in links:
    if i not in machines: machines[i] = []
    if j not in machines: machines[j] = []

    machines[i].append(p_i)
    machines[j].append(p_j)

  LF = '\n'
  for i in machines:
    m = captures[i]
    outfile.write('  subgraph cluster_%d {\n' % (m.capture_rank))
    outfile.write(f'    label = "{m.name}";{LF}')
    for pid in machines[i]:
      p = captures[i].get_process_by_pid(pid)
      p_label = captures[i].get_process_label(pid)

      outfile.write('    process_%d_%d [shape="plaintext" label=%s];\n' % (m.capture_rank, pid, p_label))
    outfile.write('  }\n')

  for (i, p_i, j, p_j, label) in links:
    outfile.write('  process_%d_%d -- process_%d_%d [label=%s];\n' %
      (i, p_i, j, p_j, label))

  write_dot_footer(outfile)
