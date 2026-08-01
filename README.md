# address-space-viewer

Record how a process's address space evolves, as JSON.

`as-trace` runs a program under `strace`, reads the memory-related syscalls
back, and reconstructs the address space they describe: a list of regions, and
the exact change each syscall made to it.  The result is a replay -- start from
nothing, apply every event's delta in order, and you have the layout at that
point in time -- which is what `viewer/index.html` animates.

```console
$ ./as-trace record -o run.json -- ./myprogram --with args
as-trace: 54 events, 1 address space(s), peak 42 regions; the program exited with 0

$ ./as-trace summary run.json
# ./myprogram --with args
# 54 events, 1 address space(s), 1 process(es)
    0  0.000000 2763516  as2 process  execve /usr/bin/python3  [-0 +12 -> 12]
    1  0.000677 2763516  as2 brk      read the break
    2  0.000763 2763516  as2 map      map 8 KiB anonymous rw-p  [-0 +1 -> 13]
    3  0.001005 2763516  as2 map      map 74.8 KiB /etc/ld.so.cache r--p  [-0 +1 -> 14]
    ...
```

Requirements: Python 3.10+, `strace` 5.2 or newer, and `/proc`.  `pyelftools`
is optional and adds the segments and sections of every mapped ELF.


## The one thing a syscall trace cannot tell you

`execve` builds an address space -- the executable, the loader, the stack, the
vdso -- and reports none of it.  Every later `mprotect` in the trace lands on
something the trace never mentioned.

The only account of that state is `/proc/<pid>/maps`, and reading it is a race:
by the time a reader is scheduled, the loader has mapped half of libc.  So the
program is held still, exactly once per exec:

```
strace --inject=execve:delay_exit=120000 -- /bin/sh -c 'exec "$0" "$@"'  ./myprogram args
```

`delay_exit` pauses the tracee after `execve` returned and before the new
program runs an instruction, which is precisely the state we are missing.
strace cannot inject into the *first* `execve` -- it performs that one itself,
before tracing is established -- hence the shell, whose `exec` is a second
`execve`.  The shell's own address space is wiped by that `exec`; it is tagged
as the trampoline and left out of the output.

**That is the whole mechanism.**  One pause per exec, and nothing else about
the recording depends on timing:

- `/proc/<pid>/auxv` is rewritten by every successful exec, so a change to it
  is what says the new image is in place.  No stopwatch, no guessing at how
  long a stop lasted.
- `maps` is read twice while the process is stopped, and a snapshot whose two
  reads disagree is dropped and taken again on the next look.
- The replay keeps a snapshot **only** if it lands on an `execve`.  Anything
  read at some other stop is discarded rather than guessed about, because
  whether the call it was standing in had run yet is not knowable from the
  trace.

`--no-baseline` removes even that pause.  The timeline then starts from an
empty address space and shows only what the syscalls say.

The pause is taken back out of the timeline (see `t` below), so an animation
runs at the speed the program really had.


## Commands

```
as-trace record [options] -- COMMAND [ARG...]   run a program, write the JSON
as-trace parse LOG [options]                    convert an existing strace log
as-trace summary run.json [--regions]           print a timeline as text
as-trace view run.json [--axis MODE]            serve the viewer and open it
as-trace shot run.json -o out.png [--event N]   draw one step, headless
```

`parse` reads a log made with `strace -f -ttt -y`; it has no snapshot, so the
timeline starts from an empty space unless `--maps PID:FILE` supplies one.  A
supplied snapshot that arrives after the space is already being tracked is
compared against the reconstruction instead of replacing it, and any
disagreement lands in `checks`.

| | |
|---|---|
| `--no-baseline` | do not pause after exec; start from an empty address space |
| `--delay-ms N` | how long the pause holds the tracee (default 120) |
| `--no-merge` | keep every mapping separate instead of coalescing neighbours |
| `--no-elf` / `--all-sections` | ELF inspection off, or include unmapped sections |
| `--strace-log FILE` | keep strace's raw output as well |
| `--shell PATH` / `--strace PATH` | which shell to use as trampoline, which strace |
| `--indent N` | `0` for one line |
| `--port N` / `--no-open` | for `view`: which port, and whether to open a browser |
| `--event N` / `--size WxH` | for `shot`: which step to draw, and how large |


## The viewer

`viewer/index.html` plays a recording back.  Open it in a browser and drop a
`run.json` onto it; there is nothing to build, nothing to install, and it
works straight off the filesystem.

```console
$ ./as-trace record -o run.json -- /bin/ls
$ ./as-trace view run.json            # serves it and opens a browser
$ xdg-open viewer/index.html          # or open it and drop run.json on the page
```

`view` exists only because a browser will not `fetch` a `file://` URL; it
serves the three files and the JSON and nothing else.  Served over HTTP the
page also takes `?trace=`, `&axis=` and `&autoplay` directly.

The map is the address space, low addresses at top, and it owns the full
height of the window: everything else is in the column beside it, so nothing
is stacked above or below the one panel whose whole point is vertical
extent.  Every address a region ever occupied keeps its place for the whole
recording, so a mapping never shifts sideways to make room for one that
appears later: what moves is what the program moved.  The unmapped stretches
between them are collapsed to a fixed height and labelled with what they
span -- the 24 TiB between the heap and the libraries is real, and drawing
it to scale would leave nothing else on screen.  `LOG` and `LINEAR` give the
axis back some or all of its true proportions.

A **block** is a contiguous stretch of memory behind one file -- or behind
no file, which is a kind of backing too -- so libc and the loader beside it
are two blocks rather than one long one, each named on its rail after what
backs it *at the step being shown*.  The same addresses hold the loader,
then nothing, then something else; a block is never named after what will be
mapped there later.  The one thing that overrides the split is a mapping
lying across it: a block is never cut where that would put one mapping into
two of them.

Every mapping gets a line it can be read on, so the map is as tall as it
needs to be and the panel scrolls.  Stepping brings what changed into view,
and leaves the map where you left it when nothing did.

Colour is what may be done to the pages -- blue read-only, amber writable,
violet executable, red both, a dashed grey box no access at all -- which is
the same thing the four characters at the right of every mapping say.  A
mapping is a range of pages rather than a section, so it is named after the
largest section in it and how many others came with it, `.text +5`, with the
file they came from left to the rail.

Beside the map: the syscall that produced the step, the regions it changed,
and the mapping under the pointer; then the whole trace; then the transport,
whose tick strip is the same thing as a scrub bar.  Arrow keys step, space
plays, `Home` and `End` jump to the ends.

A trace with more than one address space gets a row of chips above the map.
`FOLLOW` keeps the map on whichever space the current event acts on, which is
what you want while a `fork` and its child take turns; clicking a chip pins
it instead.

`INFO` opens what the recording says about itself: the command, the address
spaces, the processes, any `checks` against `/proc/pid/maps` and any
warnings.

The two fonts come from Google Fonts.  Without a network the page falls back
to whatever monospace you have, and nothing else about it needs the internet.


## Syscalls that are understood

*Layout*: `mmap` `mmap2` `old_mmap` `munmap` `mremap` `mprotect` `pkey_mprotect`
`brk` `shmat` `shmdt` (sized from `shmget`) `map_shadow_stack` `mseal`.

*Annotations*, which report a range without changing it: `madvise`
`process_madvise` `msync` `mlock` `mlock2` `munlock` `mlockall` `munlockall`,
`prctl(PR_SET_VMA_ANON_NAME)`, which names an anonymous region, `arch_prctl`,
`personality`.

*Processes*: `execve` `execveat` (a new space), `fork` `vfork` `clone` `clone3`
(a copy of the space, or a share of it when `CLONE_VM` is set), `exit`
`exit_group`, and the `+++ exited +++` and `--- SIGSEGV ---` lines -- a fault
carries its `si_addr`, which is worth seeing against the layout.

*Descriptors*: `open` `openat` `openat2` `creat` `close` `dup` `dup2` `dup3`
`memfd_create`, used only to name a file mapping when `strace -y` could not.

What is not, and cannot be:

- **stack growth**, which happens on page faults.  The kernel's `[stack]`
  therefore starts lower than the model's.
- **`remap_file_pages`**, long deprecated, which the kernel emulates with an
  ordinary `mmap`.  It is recorded and warned about, not modelled.
- **page-level state**: whether a page is resident, dirty, or shared after a
  fork.  These are regions, not pages.
- a mapping made by a process that was already running when tracing began,
  unless a `--maps` snapshot supplies it.


## The JSON

```jsonc
{
  "schema": "address-space-trace/1",
  "generator": { "tool": "as-trace", "version": "1.0",
                 "strace": "strace -- version 6.8", "command": ["strace", ...] },
  "target": { "argv": [...], "cwd": "...", "exit_code": 0,
              "traced_at": 1785601697.3, "wall_seconds": 0.41 },
  "page_size": 4096,
  "time_base": 1785601697.314556,   // unix time of t = 0
  "processes": [...], "spaces": [...], "objects": {...},
  "events": [...], "checks": [...], "warnings": [...]
}
```

**Addresses are hexadecimal strings** (`"0x7f3e873c7000"`), because a JSON
number cannot hold `0xffffffffff600000` -- the vsyscall page -- without losing
bits.  Use `BigInt(region.start)`.  Sizes are numbers, in bytes.

### events

The timeline.  `seq` is also the index into the array.

```jsonc
{
  "seq": 2,
  "t": 0.000763,              // seconds from time_base, our own pause removed
  "t_wall": 0.120763,         // as measured, when the two differ
  "pid": 2763516,
  "space": "as2",             // the address space this event acts on
  "syscall": "mmap",
  "category": "map",          // map unmap protect remap brk advise
                              // annotate process signal other
  "summary": "map 8 KiB anonymous rw-p",
  "args": { "addr": "NULL", "length": 8192, "prot": "PROT_READ|PROT_WRITE",
            "flags": "MAP_PRIVATE|MAP_ANONYMOUS", "fd": -1, "path": null,
            "offset": "0x0" },
  "result": "0x7b3e873c7000",
  "ok": false, "error": "ENOMEM",     // only on a failed call, which has no delta
  "delayed": true,                    // strace held the tracee here for us
  "delta": { "removed": ["r12"], "added": [ /* regions */ ] },
  "space_created": "as3",             // execve, or a fork
  "space_destroyed": ["as2"],         // when its last user left
  "baseline": "proc-maps",            // this delta came from /proc/pid/maps
  "raw": "2763516 1785601697.31 mmap(NULL, 8192, ...) = 0x7b3e873c7000"
}
```

To replay: keep a map of id to region; for each event, drop `delta.removed`,
add `delta.added`.  An event with no `delta` changed nothing -- a failed call,
an annotation, or an `mmap` that landed on a mapping already identical to it.
`spaces[].final_regions` is what you should end up with.

### regions

```jsonc
{
  "id": "r28",                    // stable while the region is unchanged
  "start": "0x7b3e873c7000", "end": "0x7b3e873c9000", "size": 8192,
  "prot": "rw-", "shared": false,
  "kind": "anon",                 // file anon heap stack vdso vvar vsyscall
                                  // shm shadow-stack special
  "path": "/usr/lib/libc.so.6", "offset": "0x28000",   // file mappings
  "name": "[heap]",               // or a PR_SET_VMA_ANON_NAME
  "flags": ["MAP_NORESERVE"],     // only flags the kernel keeps in vm_flags
  "sealed": true,
  "since": 2,                     // the event that produced it
  "origin": ["r12"],              // the regions it came from, for animating
  "object": "/usr/lib/libc.so.6", // an entry in `objects`
  "bias": "0x7b3e87000000",       // section address + bias = where it landed
  "zero_fill": true               // anonymous, but it is a PT_LOAD's .bss
}
```

An id is kept as long as the region is untouched, so a viewer can animate one
rather than redraw the lot.  An `mprotect` of the middle of a region removes
one id and adds three, each naming the original in `origin`.

Neighbouring regions the kernel would hold as a single VMA are merged, so the
layout matches `/proc/pid/maps`.  `--no-merge` turns that off.

### objects

Every ELF behind a mapping, read once:

```jsonc
"/usr/lib/libc.so.6": {
  "path": "...", "type": "ET_DYN", "machine": "EM_X86_64", "entry": "0x29ec0",
  "soname": "libc.so.6", "build_id": "8a19b8...", "interp": "/lib64/ld-linux...",
  "segments": [ { "type": "PT_LOAD", "flags": "r-x", "offset": "0x28000",
                  "vaddr": "0x28000", "filesz": 1531161, "memsz": 1531161,
                  "align": 4096 } ],
  "sections": [ { "name": ".text", "type": "SHT_PROGBITS", "flags": "AX",
                  "addr": "0x29ec0", "offset": "0x29ec0", "size": 1409475 } ]
}
```

A section lands at `bias + addr` of the region that names the object, which is
how a viewer draws `.text`, `.rodata` and `.data` inside a mapping.  Only
`SHF_ALLOC` sections are listed -- the rest are in the file but never mapped --
unless `--all-sections`.  `.bss` is reached through the anonymous region the
loader places after the last `PT_LOAD`, which carries `zero_fill`.

### spaces and processes

```jsonc
"spaces": [ { "id": "as2", "reason": "execve",  // execve fork unknown
              "creator": 2763516, "created_by": 0, "destroyed_by": 53,
              "baseline": "proc-maps",          // proc-maps inherited none
              "members": [2763516],             // everyone who ever used it
              "peak_regions": 42, "peak_bytes": 292532224,
              "final_regions": [ /* regions */ ] } ],
"processes": [ { "pid": 2763516, "parent": null, "exe": "/usr/bin/python3",
                 "argv": "[\"python3\", \"-c\", \"print(1)\"]",
                 "thread_of": 2763516,          // when it shares a space
                 "exit": "exited with 0" } ]
```

A threaded program has one space with several members; a program that forks has
one space per child, each starting as a copy with its own region ids.
`space_created` and `space_destroyed` on the events say when one begins and
ends, which is how the viewer knows to follow a `fork` into its child.

`baseline` says where a space's starting layout came from: `proc-maps` for one
read at an exec, `inherited` for a copy made by fork, `none` when neither was
available -- in which case its regions begin at whatever the syscalls map next,
and `warnings` says so.


## Nix

```console
$ nix run github:…/address-space-viewer -- record -o run.json -- /bin/ls
$ nix develop            # python, pyelftools, strace, playwright and a browser
$ nix flake check        # the test suite
```

The package is the command and the viewer together; `strace` comes with it.
`nix develop` adds what only `as-trace shot` needs -- playwright and a
chromium -- which the tool finds through `PLAYWRIGHT_BROWSERS_PATH`.


## Tests

```console
$ python3 -m unittest discover -s tests
Ran 71 tests in 1.5s
OK
```

The parser and the model are driven by hand-written traces, which is the only
way to reach what a live program will not produce on demand: a failing
`mremap`, a `clone` whose child is printed before the `clone` returns, a
`vfork` child exec'ing out of its parent's address space.

The end-to-end test asks the kernel instead, and needs no extra pause to do it:
it records `cat /proc/self/maps`, which prints the kernel's own account of the
address space at the moment it read the file, and asserts that replaying the
deltas passes through exactly that layout.  It is also the only test that
exercises the JSON the way the viewer will.
