"""Reconstruct a process address space from an strace log.

The pieces:

  syscalls   the syscall sets we ask strace for, and flag/constant decoding
  straceout  strace's text output -> structured records
  procmaps   /proc/<pid>/maps -> regions, for the initial state and for checks
  space      the address space itself: regions, and the operations on them
  replay     records + snapshots -> processes, address spaces, timed events
  record     running strace, and catching the tracee stopped to snapshot maps
  libdebug_record  the same, with libdebug driving ptrace itself
  cli        the command line

Nothing here imports anything outside the standard library, except
libdebug_record, which is only reached when that backend is asked for.
"""

__version__ = "1.0"
SCHEMA = "address-space-trace/1"
