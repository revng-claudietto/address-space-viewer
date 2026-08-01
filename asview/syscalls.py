"""What we ask strace for, and how to read the constants it prints back.

strace decodes flags symbolically (MAP_PRIVATE|MAP_ANONYMOUS), so the tables
here map names to bits rather than the other way round.  Anything strace could
not decode comes through as a hex literal and is preserved as-is.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# The syscalls we ask strace to report.
# --------------------------------------------------------------------------- #

# Calls that create, destroy, resize or re-label a mapping.
MEMORY = [
    "mmap", "mmap2", "old_mmap", "munmap", "mremap",
    "mprotect", "pkey_mprotect", "pkey_alloc", "pkey_free",
    "brk", "mseal", "remap_file_pages", "map_shadow_stack",
    "shmat", "shmdt", "shmget", "shmctl",
    # No layout change, but they say something about a range that a viewer
    # wants to show: pages dropped, pages pinned, contents flushed.
    "madvise", "process_madvise", "msync",
    "mlock", "mlock2", "munlock", "mlockall", "munlockall",
]

# Calls that create or destroy an address space, or a user of one.
PROCESS = [
    "execve", "execveat",
    "fork", "vfork", "clone", "clone3",
    "exit", "exit_group",
    "prctl", "arch_prctl", "personality",
]

# Only needed to name a mapping when strace was not asked to decode file
# descriptors (-y), or when it could not: a memfd has no path on disk.
DESCRIPTORS = [
    "open", "openat", "openat2", "creat", "close",
    "dup", "dup2", "dup3", "fcntl", "fcntl64",
    "memfd_create", "memfd_secret", "userfaultfd", "io_uring_setup",
]

TRACED = MEMORY + PROCESS + DESCRIPTORS

# Fallback for an strace too old to know some of the names above.
TRACED_CLASSES = "%memory,%process,%desc"

# Where we ask strace to pause the tracee so we can read /proc/<pid>/maps:
# after an execve returns, where the new address space exists and not one
# instruction of the new program has run yet.  That state is the one thing a
# syscall trace cannot tell us, and it is the only pause we ask for.
#
# The very first execve is strace's own, and cannot be injected into; a shell
# trampoline turns the program's own exec into a second one.  See record.py.
DELAY_AT_EXIT = ["execve", "execveat"]


# --------------------------------------------------------------------------- #
# Constants.
# --------------------------------------------------------------------------- #

PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4

PROT_BITS = {
    "PROT_NONE": 0,
    "PROT_READ": PROT_READ,
    "PROT_WRITE": PROT_WRITE,
    "PROT_EXEC": PROT_EXEC,
    "PROT_SEM": 0x8,
    "PROT_GROWSDOWN": 0x01000000,
    "PROT_GROWSUP": 0x02000000,
}

MAP_SHARED = "MAP_SHARED"
MAP_SHARED_VALIDATE = "MAP_SHARED_VALIDATE"
MAP_ANONYMOUS = {"MAP_ANONYMOUS", "MAP_ANON"}

# Flags that outlive the call because the kernel keeps them in vm_flags, and
# so distinguish two neighbouring mappings that would otherwise be one VMA.
# The rest describe how the call behaved -- MAP_FIXED, MAP_POPULATE -- or ask
# for a placement -- MAP_32BIT -- and the event keeps them either way.
#
# MAP_STACK is deliberately absent: Linux accepts it and does nothing with it,
# so a thread stack merges with whatever anonymous mapping it lands next to.
STICKY_MAP_FLAGS = frozenset({
    "MAP_GROWSDOWN", "MAP_LOCKED", "MAP_NORESERVE", "MAP_HUGETLB", "MAP_SYNC",
})

MREMAP_MAYMOVE = "MREMAP_MAYMOVE"
MREMAP_FIXED = "MREMAP_FIXED"
MREMAP_DONTUNMAP = "MREMAP_DONTUNMAP"

CLONE_VM = "CLONE_VM"
CLONE_FILES = "CLONE_FILES"
CLONE_THREAD = "CLONE_THREAD"
CLONE_VFORK = "CLONE_VFORK"


def prot_bits(text: str) -> int:
    """PROT_READ|PROT_EXEC -> 5.  Undecoded hex contributes its own bits."""
    bits = 0
    for name, extra in _terms(text):
        bits |= PROT_BITS.get(name, 0) | extra
    return bits


def prot_string(bits: int) -> str:
    return ("r" if bits & PROT_READ else "-") + \
           ("w" if bits & PROT_WRITE else "-") + \
           ("x" if bits & PROT_EXEC else "-")


def flag_names(text: str) -> tuple[str, ...]:
    """MAP_PRIVATE|MAP_ANONYMOUS|0x40000 -> ('MAP_PRIVATE', ..., '0x40000')."""
    out = []
    for name, extra in _terms(text):
        out.append(name if name else hex(extra))
    return tuple(out)


def _terms(text: str):
    """Yield (name, numeric_value) for each |-separated term."""
    for term in (text or "").split("|"):
        term = term.strip()
        if not term:
            continue
        try:
            yield "", int(term, 0)
        except ValueError:
            yield term, 0


def is_anonymous(flags: tuple[str, ...]) -> bool:
    return any(f in MAP_ANONYMOUS for f in flags)


def is_shared(flags: tuple[str, ...]) -> bool:
    return MAP_SHARED in flags or MAP_SHARED_VALIDATE in flags
