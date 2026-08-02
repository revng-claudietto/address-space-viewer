"""Tests for as-trace.

Run them with:

    python3 -m unittest discover -s tests

The parser and the model are tested against hand-written traces, which is the
only way to reach cases a live program will not produce on demand -- a failing
mremap, a clone whose child is printed before the clone returns.  The last
class runs the real thing and leans on the tool's own checkpoints: every
delayed stop compares the reconstruction against /proc/pid/maps, so a passing
recording is a comparison against the kernel, not against our expectations.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from asview import elfinfo, procmaps, replay, space, straceout, syscalls  # noqa: E402
from asview.space import Desc  # noqa: E402

AS_TRACE = os.path.join(ROOT, "as-trace")


def replay_text(text: str, snapshots=(), **kw) -> replay.Machine:
    space.set_page_size(4096)
    records = straceout.Parser().feed(text)
    machine = replay.Machine(**kw)
    machine.run(records, list(snapshots))
    return machine


def layout(machine: replay.Machine, ident: str = "as0") -> list[Desc]:
    return machine.spaces[ident].layout


def extents(machine: replay.Machine, ident: str = "as0") -> list[tuple[int, int, str]]:
    return [(d.start, d.end, syscalls.prot_string(d.prot))
            for d in layout(machine, ident)]


class SplitArguments(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(
            straceout.split_args("NULL, 8192, PROT_READ|PROT_WRITE, -1, 0"),
            ["NULL", "8192", "PROT_READ|PROT_WRITE", "-1", "0"])

    def test_nested_structures_are_one_argument(self):
        self.assertEqual(
            straceout.split_args("{flags=CLONE_VM|CLONE_FS, exit_signal=0}, 88"),
            ["{flags=CLONE_VM|CLONE_FS, exit_signal=0}", "88"])

    def test_comma_inside_a_string(self):
        self.assertEqual(straceout.split_args('"a, b", 1'), ['"a, b"', "1"])

    def test_comma_inside_a_descriptor_path(self):
        self.assertEqual(
            straceout.split_args('3</tmp/a,b.so>, 0'), ["3</tmp/a,b.so>", "0"])

    def test_modified_argument_arrow_does_not_unbalance(self):
        self.assertEqual(
            straceout.split_args("{a=1} => {b=2}, 3"), ["{a=1} => {b=2}", "3"])


class ParseLines(unittest.TestCase):
    def parse(self, text: str) -> list[straceout.Record]:
        return straceout.Parser().feed(text)

    def test_pid_time_and_result(self):
        rec, = self.parse("42 1000.5 mmap(NULL, 4096) = 0x7f0000000000")
        self.assertEqual((rec.pid, rec.name, rec.ret), (42, "mmap", 0x7F0000000000))
        self.assertAlmostEqual(rec.time, 1000.5)

    def test_error(self):
        rec, = self.parse('1 1.0 mmap(NULL, 1) = -1 ENOMEM (Cannot allocate memory)')
        self.assertEqual((rec.ret, rec.error, rec.ok), (-1, "ENOMEM", False))

    def test_descriptor_decoration_on_the_result(self):
        rec, = self.parse('1 1.0 openat(AT_FDCWD, "/x", O_RDONLY) = 3</x>')
        self.assertEqual((rec.ret, rec.ret_path), (3, "/x"))

    def test_injected_delay_marker(self):
        rec, = self.parse("1 1.0 brk(NULL) = 0x1000 (DELAYED)")
        self.assertEqual((rec.ret, rec.delayed, rec.error), (0x1000, True, None))

    def test_unavailable_result(self):
        rec, = self.parse("1 1.0 exit_group(0) = ?")
        self.assertEqual((rec.name, rec.ret), ("exit_group", None))

    def test_unfinished_and_resumed_join(self):
        records = self.parse(
            "1 1.0 clone(child_stack=NULL, flags=CLONE_VM <unfinished ...>\n"
            "2 1.1 brk(NULL) = 0x1000\n"
            "1 1.2 <... clone resumed>) = 2\n")
        names = [(r.pid, r.name, r.ret) for r in records]
        self.assertEqual(names, [(2, "brk", 0x1000), (1, "clone", 2)])
        clone = records[-1]
        self.assertEqual(straceout.keyword_args(clone.args)["flags"], "CLONE_VM")
        self.assertAlmostEqual(clone.time, 1.0)      # timed at entry, not exit

    def test_unfinished_without_resume_is_kept(self):
        rec, = self.parse("1 1.0 read(3 <unfinished ...>")
        self.assertTrue(rec.unfinished)

    def test_signal_and_exit(self):
        records = self.parse(
            "1 1.0 --- SIGSEGV {si_signo=SIGSEGV, si_addr=0x10} ---\n"
            "1 1.1 +++ killed by SIGSEGV +++\n")
        self.assertEqual([r.kind for r in records], ["signal", "exit"])
        self.assertEqual(records[0].name, "SIGSEGV")
        self.assertEqual(records[1].detail, "killed by SIGSEGV")

    def test_notes_are_not_calls(self):
        rec, = self.parse("strace: Process 2 attached")
        self.assertEqual(rec.kind, "note")

    def test_quoted_unescapes(self):
        self.assertEqual(straceout.quoted('"a\\nb"'), "a\nb")


class Layouts(unittest.TestCase):
    def setUp(self):
        space.set_page_size(4096)

    def anon(self, start, end, prot=3):
        return Desc(start=start, end=end, prot=prot)

    def test_carve_punches_a_hole(self):
        out = space.carve([self.anon(0, 0x4000)], 0x1000, 0x2000)
        self.assertEqual([(d.start, d.end) for d in out],
                         [(0, 0x1000), (0x2000, 0x4000)])

    def test_carve_advances_the_file_offset(self):
        d = Desc(start=0x1000, end=0x3000, prot=1, path="/lib/x", offset=0x5000)
        out = space.carve([d], 0x1000, 0x2000)
        self.assertEqual((out[0].start, out[0].offset), (0x2000, 0x6000))

    def test_anonymous_offsets_do_not_move(self):
        out = space.carve([self.anon(0x1000, 0x3000)], 0x1000, 0x2000)
        self.assertEqual(out[0].offset, 0)

    def test_place_replaces_what_was_there(self):
        out = space.place([self.anon(0, 0x4000)], self.anon(0x1000, 0x2000, prot=1))
        self.assertEqual([(d.start, d.end, d.prot) for d in out],
                         [(0, 0x1000, 3), (0x1000, 0x2000, 1), (0x2000, 0x4000, 3)])

    def test_merge_joins_identical_neighbours(self):
        out = space.merge([self.anon(0, 0x1000), self.anon(0x1000, 0x2000)])
        self.assertEqual([(d.start, d.end) for d in out], [(0, 0x2000)])

    def test_merge_respects_file_continuity(self):
        a = Desc(start=0, end=0x1000, prot=1, path="/lib/x", offset=0)
        contiguous = Desc(start=0x1000, end=0x2000, prot=1, path="/lib/x",
                          offset=0x1000)
        apart = Desc(start=0x1000, end=0x2000, prot=1, path="/lib/x", offset=0x9000)
        self.assertEqual(len(space.merge([a, contiguous])), 1)
        self.assertEqual(len(space.merge([a, apart])), 2)

    def test_map_stack_does_not_keep_neighbours_apart(self):
        # Linux accepts MAP_STACK and does nothing with it, so a thread stack
        # is one VMA with whatever anonymous mapping it lands next to.
        a = Desc(start=0, end=0x1000, prot=3)
        b = Desc(start=0x1000, end=0x2000, prot=3,
                 flags=tuple(f for f in ("MAP_STACK",)
                             if f in syscalls.STICKY_MAP_FLAGS))
        self.assertEqual(len(space.merge([a, b])), 1)

    def test_reserved_flags_do_keep_neighbours_apart(self):
        a = Desc(start=0, end=0x1000, prot=3)
        b = Desc(start=0x1000, end=0x2000, prot=3, flags=("MAP_NORESERVE",))
        self.assertEqual(len(space.merge([a, b])), 2)

    def test_merge_keeps_different_protections_apart(self):
        out = space.merge([self.anon(0, 0x1000), self.anon(0x1000, 0x2000, prot=1)])
        self.assertEqual(len(out), 2)


class RegionIdentity(unittest.TestCase):
    def setUp(self):
        space.set_page_size(4096)
        self.n = 0
        self.space = space.AddressSpace("as0", self.ident)

    def ident(self) -> str:
        self.n += 1
        return f"r{self.n}"

    def test_unchanged_regions_keep_their_id(self):
        first = [Desc(start=0, end=0x1000, prot=1)]
        self.space.rebuild(first, 0)
        kept = self.space.regions[0].id
        self.space.rebuild(first + [Desc(start=0x8000, end=0x9000, prot=1)], 1)
        self.assertEqual(self.space.regions[0].id, kept)

    def test_a_split_names_its_origin(self):
        self.space.rebuild([Desc(start=0, end=0x3000, prot=1)], 0)
        original = self.space.regions[0].id
        removed, added = self.space.rebuild(
            [Desc(start=0, end=0x1000, prot=1),
             Desc(start=0x1000, end=0x2000, prot=3),
             Desc(start=0x2000, end=0x3000, prot=1)], 1)
        self.assertEqual(removed, [original])
        self.assertEqual(len(added), 3)
        for region in added:
            self.assertEqual(region.origin, (original,))


class Syscalls(unittest.TestCase):
    """The model, driven by hand-written traces."""

    def test_mmap_rounds_up_to_a_page(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 100, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000")
        self.assertEqual(extents(m), [(0x10000, 0x11000, "r--")])

    def test_a_failed_call_changes_nothing(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = -1 ENOMEM (Cannot allocate memory)")
        self.assertEqual(extents(m), [])
        self.assertEqual(m.events[0]["ok"], False)

    def test_mmap_over_an_existing_mapping_replaces_it(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 16384, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 mmap(0x11000, 4096, PROT_READ|PROT_WRITE,"
            " MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) = 0x11000\n")
        self.assertEqual(extents(m), [(0x10000, 0x11000, "r--"),
                                      (0x11000, 0x12000, "rw-"),
                                      (0x12000, 0x14000, "r--")])

    def test_mprotect_splits_in_three(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 12288, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 mprotect(0x11000, 4096, PROT_READ|PROT_EXEC) = 0\n")
        self.assertEqual(extents(m), [(0x10000, 0x11000, "r--"),
                                      (0x11000, 0x12000, "r-x"),
                                      (0x12000, 0x13000, "r--")])

    def test_munmap_leaves_a_hole(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 12288, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 munmap(0x11000, 4096) = 0\n")
        self.assertEqual(extents(m), [(0x10000, 0x11000, "r--"),
                                      (0x12000, 0x13000, "r--")])

    def test_file_mapping_takes_its_path_from_the_descriptor(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3</lib/libc.so.6>,"
            " 0x2000) = 0x10000")
        region = layout(m)[0]
        self.assertEqual((region.path, region.offset, region.kind),
                         ("/lib/libc.so.6", 0x2000, "file"))

    def test_file_mapping_falls_back_to_the_open_it_saw(self):
        m = replay_text(
            '1 1.0 openat(AT_FDCWD, "/lib/libm.so", O_RDONLY) = 4\n'
            "1 1.1 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 4, 0) = 0x10000\n")
        self.assertEqual(layout(m)[0].path, "/lib/libm.so")

    def test_brk_grows_and_shrinks_the_heap(self):
        m = replay_text(
            "1 1.0 brk(NULL) = 0x10000\n"
            "1 1.1 brk(0x14000) = 0x14000\n")
        self.assertEqual(extents(m), [(0x10000, 0x14000, "rw-")])
        self.assertEqual(layout(m)[0].name, "[heap]")

        m = replay_text(
            "1 1.0 brk(NULL) = 0x10000\n"
            "1 1.1 brk(0x14000) = 0x14000\n"
            "1 1.2 brk(0x12000) = 0x12000\n")
        self.assertEqual(extents(m), [(0x10000, 0x12000, "rw-")])

    def test_brk_back_to_the_start_removes_the_heap(self):
        m = replay_text(
            "1 1.0 brk(NULL) = 0x10000\n"
            "1 1.1 brk(0x14000) = 0x14000\n"
            "1 1.2 brk(0x10000) = 0x10000\n")
        self.assertEqual(extents(m), [])

    def test_mremap_moves_a_mapping(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 mremap(0x10000, 4096, 8192, MREMAP_MAYMOVE) = 0x20000\n")
        self.assertEqual(extents(m), [(0x20000, 0x22000, "r--")])

    def test_mremap_in_place_shrink(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 8192, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 mremap(0x10000, 8192, 4096, 0) = 0x10000\n")
        self.assertEqual(extents(m), [(0x10000, 0x11000, "r--")])

    def test_shm_uses_the_size_from_shmget(self):
        m = replay_text(
            "1 1.0 shmget(IPC_PRIVATE, 8192, IPC_CREAT|0600) = 7\n"
            "1 1.1 shmat(7, NULL, 0) = 0x10000\n")
        self.assertEqual(extents(m), [(0x10000, 0x12000, "rw-")])
        self.assertEqual(layout(m)[0].kind, "shm")
        m = replay_text(
            "1 1.0 shmget(IPC_PRIVATE, 8192, IPC_CREAT|0600) = 7\n"
            "1 1.1 shmat(7, NULL, 0) = 0x10000\n"
            "1 1.2 shmdt(0x10000) = 0\n")
        self.assertEqual(extents(m), [])

    def test_anonymous_naming(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            '1 1.1 prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x10000, 4096, "arena")'
            " = 0\n")
        self.assertEqual(layout(m)[0].name, "arena")

    def test_madvise_is_recorded_without_changing_the_layout(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 8192, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 madvise(0x10000, 4096, MADV_DONTNEED) = 0\n")
        self.assertEqual(extents(m), [(0x10000, 0x12000, "r--")])
        self.assertEqual(m.events[-1]["category"], "advise")
        self.assertNotIn("delta", m.events[-1])

    def test_mseal_marks_the_range(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 mseal(0x10000, 4096, 0) = 0\n")
        self.assertTrue(layout(m)[0].sealed)


class Processes(unittest.TestCase):
    def test_a_thread_shares_the_space(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 clone(child_stack=0x1000, flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND)"
            " = 2\n")
        self.assertEqual(m.procs[2].space, m.procs[1].space)
        self.assertEqual(m.procs[2].thread_of, 1)
        self.assertEqual(len(m.spaces), 1)

    def test_a_fork_copies_the_space(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 clone(child_stack=NULL, flags=SIGCHLD) = 2\n")
        child = m.procs[2].space
        self.assertNotEqual(child, m.procs[1].space)
        self.assertEqual(extents(m, child), extents(m, m.procs[1].space))
        # Same shape, but its own regions, so a viewer can move them apart.
        self.assertNotEqual({r.id for r in m.spaces[child].regions},
                            {r.id for r in m.spaces[m.procs[1].space].regions})

    def test_a_forked_child_diverges(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 clone(child_stack=NULL, flags=SIGCHLD) = 2\n"
            "2 1.2 munmap(0x10000, 4096) = 0\n")
        self.assertEqual(extents(m, m.procs[2].space), [])
        self.assertEqual(len(extents(m, m.procs[1].space)), 1)

    def test_clone3_flags_are_read_from_the_structure(self):
        m = replay_text(
            "1 1.0 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND,"
            " child_tid=0x7f00, stack=0x7000, stack_size=0x1000}, 88) = 2\n")
        self.assertEqual(m.procs[2].space, m.procs[1].space)

    def test_execve_starts_a_new_space(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            '1 1.1 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n')
        self.assertEqual(extents(m, m.procs[1].space), [])
        self.assertEqual(len(m.spaces), 2)

    def test_a_vfork_child_exec_leaves_the_parent_its_space(self):
        m = replay_text(
            "1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.1 vfork() = 2\n"
            '2 1.2 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n'
            "2 1.3 +++ exited with 0 +++\n"
            "1 1.4 munmap(0x10000, 4096) = 0\n")
        self.assertEqual(m.warnings, [])
        self.assertEqual(extents(m, "as0"), [])          # unmapped at the end
        self.assertNotEqual(m.procs[2].space, "as0")

    def test_a_child_seen_before_its_clone_returns(self):
        m = replay_text(
            "1 1.0 clone(child_stack=NULL, flags=CLONE_VM <unfinished ...>\n"
            "2 1.1 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.2 <... clone resumed>) = 2\n")
        self.assertEqual(m.procs[2].space, m.procs[1].space)
        self.assertEqual(m.warnings, [])

    def test_the_last_thread_out_destroys_the_space(self):
        m = replay_text(
            "1 1.0 clone(child_stack=0x1000, flags=CLONE_VM|CLONE_THREAD) = 2\n"
            "2 1.1 +++ exited with 0 +++\n"
            "1 1.2 +++ exited with 0 +++\n")
        self.assertIsNotNone(m.info["as0"].destroyed_by)

    def test_a_segfault_is_reported_with_its_address(self):
        m = replay_text(
            "1 1.0 --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR,"
            " si_addr=0x1234} ---\n")
        self.assertEqual(m.events[0]["category"], "signal")
        self.assertEqual(m.events[0]["args"]["si_addr"], "0x1234")


class Baseline(unittest.TestCase):
    MAPS = ("00010000-00012000 r-xp 00000000 00:1a 1 /bin/x\n"
            "7ffff0000000-7ffff0021000 rw-p 00000000 00:00 0 [stack]\n")

    def test_maps_becomes_the_delta_of_the_execve(self):
        snapshot = replay.Snapshot(time=1.15, pid=1, exe="/bin/x", text=self.MAPS)
        m = replay_text(
            '1 1.1 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n'
            "1 1.2 brk(NULL) = 0x20000\n",
            snapshots=[snapshot])
        birth = m.events[0]
        self.assertEqual(birth["syscall"], "execve")
        self.assertEqual(birth["baseline"], "proc-maps")
        self.assertEqual(len(birth["delta"]["added"]), 2)
        self.assertEqual(m.info[m.procs[1].space].baseline, "proc-maps")

    def test_a_later_snapshot_becomes_a_check(self):
        first = replay.Snapshot(time=1.15, pid=1, exe="/bin/x", text=self.MAPS)
        second = replay.Snapshot(time=1.25, pid=1, exe="/bin/x", text=self.MAPS,
                                 supplied=True)
        m = replay_text(
            '1 1.1 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n'
            "1 1.2 brk(NULL) = 0x20000\n"
            "1 1.3 munmap(0x10000, 4096) = 0\n",
            snapshots=[first, second])
        self.assertEqual(len(m.checks), 1)
        self.assertTrue(m.checks[0]["match"])

    def test_a_check_notices_a_difference(self):
        maps = self.MAPS + "00030000-00031000 rw-p 00000000 00:00 0\n"
        m = replay_text(
            '1 1.1 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n'
            "1 1.2 brk(NULL) = 0x20000\n"
            "1 1.3 munmap(0x10000, 4096) = 0\n",
            snapshots=[replay.Snapshot(time=1.15, pid=1, exe=None, text=self.MAPS),
                       replay.Snapshot(time=1.25, pid=1, exe=None, text=maps,
                                       supplied=True)])
        self.assertFalse(m.checks[0]["match"])
        self.assertEqual(m.checks[0]["differences"][0]["model"], None)

    def test_a_snapshot_that_lands_elsewhere_is_dropped(self):
        # Read at some stop that is not an exec: whether the call it is
        # standing in has run yet cannot be told from the trace.
        m = replay_text(
            '1 1.1 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n'
            "1 1.2 brk(NULL) = 0x20000\n"
            "1 1.3 munmap(0x10000, 4096) = 0\n",
            snapshots=[replay.Snapshot(time=1.15, pid=1, exe=None, text=self.MAPS),
                       replay.Snapshot(time=1.25, pid=1, exe=None, text=self.MAPS)])
        self.assertEqual(m.checks, [])

    def test_stack_growth_is_an_expected_difference(self):
        grown = ("00010000-00012000 r-xp 00000000 00:1a 1 /bin/x\n"
                 "7fffefff0000-7ffff0021000 rw-p 00000000 00:00 0 [stack]\n")
        result = procmaps.compare(procmaps.parse(self.MAPS), procmaps.parse(grown))
        self.assertTrue(result["match"])
        self.assertEqual(len(result["expected_differences"]), 1)


class Timeline(unittest.TestCase):
    def test_injected_stops_are_taken_back_out(self):
        m = replay_text(
            '1 1.0 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0 (DELAYED)\n'
            "1 1.2 brk(NULL) = 0x20000\n",
            injected_delay=0.1)
        doc = m.document({})
        self.assertEqual(doc["events"][0]["t"], 0.0)
        self.assertAlmostEqual(doc["events"][1]["t"], 0.1)      # 0.2 wall - 0.1
        self.assertAlmostEqual(doc["events"][1]["t_wall"], 0.2)

    def test_overlapping_stops_count_once(self):
        m = replay_text(
            "1 1.0 brk(NULL) = 0x1000 (DELAYED)\n"
            "2 1.0 brk(NULL) = 0x1000 (DELAYED)\n"
            "1 1.3 munmap(0x10000, 4096) = 0\n",
            injected_delay=0.1)
        doc = m.document({})
        self.assertAlmostEqual(doc["events"][-1]["t"], 0.2)     # not 0.1

    def test_the_timeline_never_goes_backwards(self):
        m = replay_text(
            "1 1.0 brk(NULL) = 0x1000 (DELAYED)\n"
            "2 1.05 brk(NULL) = 0x1000\n"
            "1 1.2 brk(NULL) = 0x1000\n",
            injected_delay=0.1)
        times = [e["t"] for e in m.document({})["events"]]
        self.assertEqual(times, sorted(times))


class Document(unittest.TestCase):
    def build(self) -> dict:
        m = replay_text(
            '1 1.0 execve("/bin/x", ["x"], 0x0 /* 0 vars */) = 0\n'
            "1 1.1 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
            " = 0x10000\n"
            "1 1.2 +++ exited with 0 +++\n")
        return m.document({"target": {"argv": ["/bin/x"]}})

    def test_shape(self):
        doc = self.build()
        for key in ("schema", "generator", "page_size", "processes", "spaces",
                    "events", "checks", "warnings", "objects"):
            self.assertIn(key, doc)
        self.assertTrue(json.dumps(doc))            # serialisable

    def test_sequence_numbers_are_indices(self):
        doc = self.build()
        self.assertEqual([e["seq"] for e in doc["events"]],
                         list(range(len(doc["events"]))))

    def test_addresses_are_hexadecimal_strings(self):
        doc = self.build()
        region = doc["events"][1]["delta"]["added"][0]
        self.assertEqual(region["start"], "0x10000")
        self.assertIsInstance(region["size"], int)

    def test_replaying_the_deltas_reaches_the_final_layout(self):
        doc = self.build()
        live: dict[str, dict] = {}
        for ev in doc["events"]:
            delta = ev.get("delta") or {}
            for ident in delta.get("removed", []):
                live.pop(ident, None)
            for region in delta.get("added", []):
                live[region["id"]] = region
        space_id = doc["spaces"][0]["id"]
        final = {r["id"] for r in doc["spaces"][0]["final_regions"]}
        self.assertEqual({r["id"] for r in live.values()
                          if r["id"] in final or True} & final, final)
        self.assertEqual(len(live), len(final))
        self.assertEqual(space_id, doc["events"][0]["space"])


class Elf(unittest.TestCase):
    @unittest.skipUnless(elfinfo.HAVE_PYELFTOOLS, "pyelftools is not installed")
    def test_bias_and_sections_of_a_real_binary(self):
        path = os.path.realpath(sys.executable)
        library = elfinfo.Library()
        obj = library._object(path)
        self.assertIsNotNone(obj)
        self.assertTrue(obj.json["sections"])
        self.assertTrue(any(s["name"] == ".text" for s in obj.json["sections"]))

        # A window onto the first PT_LOAD, placed at an arbitrary base.
        offset, _, vaddr, _ = obj.loads[0]
        base = 0x7F0000000000
        desc = Desc(start=base, end=base + 0x1000, prot=1, path=path,
                    offset=space.page_down(offset), kind="file")
        annotation = library.annotate(desc, [desc])
        self.assertEqual(annotation["object"], path)
        self.assertEqual(int(annotation["bias"], 16),
                         base - space.page_down(vaddr))

    @unittest.skipUnless(elfinfo.HAVE_PYELFTOOLS, "pyelftools is not installed")
    def test_one_bias_for_every_window_onto_an_image(self):
        """The last file page of the read-only segment is also the first of
        the writable one, mapped a page higher.  Both windows name the same
        file offset, so the offset alone cannot say which segment a window
        is -- and answering the wrong one puts every section it holds a page
        from where it really is.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = build_demo(tmp)
            if path is None:
                self.skipTest("nothing to compile the demo with")
            library = elfinfo.Library()
            obj = library._object(path)
            base = 0x7F0000000000
            image = [Desc(start=base + space.page_down(vaddr),
                          end=base + space.page_up(vaddr + filesz),
                          prot=1, path=path, offset=space.page_down(p_offset),
                          kind="file")
                     for p_offset, filesz, vaddr, _ in obj.loads]
            self.assertLess(len({w.offset for w in image}), len(image),
                            "the demo is meant to share a file page")
            for window in image:
                self.assertEqual(int(library.annotate(window, image)["bias"], 16),
                                 base)

    @unittest.skipUnless(elfinfo.HAVE_PYELFTOOLS, "pyelftools is not installed")
    def test_only_allocated_sections_by_default(self):
        path = os.path.realpath(sys.executable)
        names = {s["name"] for s in elfinfo.Library()._object(path).json["sections"]}
        everything = {s["name"] for s in
                      elfinfo.Library(all_sections=True)._object(path).json["sections"]}
        self.assertNotIn(".shstrtab", names)          # present, never mapped
        self.assertIn(".shstrtab", everything)
        self.assertLess(names, everything)

    def test_a_missing_file_is_not_fatal(self):
        library = elfinfo.Library()
        desc = Desc(start=0x1000, end=0x2000, prot=1, path="/nowhere/at/all",
                    kind="file")
        self.assertEqual(library.annotate(desc, [desc]), {})


# The programs recorded below are named by absolute path on purpose: what is
# being tested is a recording of a real image the kernel mapped, so which
# echo it is matters.  A build sandbox has none of them, hence the guard.
NEEDED = ["/bin/sh", "/bin/echo", "/bin/cat"]

DEMO = os.path.join(ROOT, "demo", "demo.c")


def build_demo(into: str) -> str | None:
    """Compile the demo program, or say there is nothing to compile with."""
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    if compiler is None or not os.path.exists(DEMO):
        return None
    out = os.path.join(into, "demo")
    done = subprocess.run([compiler, "-O0", "-g", "-o", out, DEMO],
                          capture_output=True, text=True)
    return out if done.returncode == 0 else None


@unittest.skipUnless(os.path.exists("/proc/self/maps"), "/proc is not mounted")
@unittest.skipUnless(all(map(os.path.exists, NEEDED)),
                     f"needs {', '.join(NEEDED)}")
class EndToEnd(unittest.TestCase):
    """Record a real program and let the kernel do the judging.

    Every test here is run against both recorders.  They share the model,
    the replay and the output, so what differs is only how the syscalls and
    the exec baseline were collected -- which is exactly what a second
    backend has to get right for the rest to mean anything.
    """

    BACKEND = "strace"

    @classmethod
    def setUpClass(cls):
        if cls.BACKEND == "strace" and not shutil.which("strace"):
            raise unittest.SkipTest("strace is not installed")
        if cls.BACKEND == "libdebug" and not importlib.util.find_spec("libdebug"):
            raise unittest.SkipTest("libdebug is not installed")

    def record(self, *args: str, command: str = "record") -> dict:
        # Not to stdout: the traced program writes there too.
        with tempfile.NamedTemporaryFile(suffix=".json") as out:
            done = subprocess.run(
                [sys.executable, AS_TRACE, command, "-o", out.name,
                 *self.flags(command), *args],
                capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            with open(out.name) as written:
                return json.load(written)

    def flags(self, command: str) -> list[str]:
        return ["--backend", self.BACKEND] if command == "record" else []

    def test_echo(self):
        doc = self.record("--", "/bin/echo", "hello")
        self.assertEqual(doc["target"]["exit_code"], 0)
        self.assertEqual(len(doc["spaces"]), 1)
        self.assertTrue(doc["events"])
        self.assertEqual(doc["events"][0]["syscall"], "execve")
        self.assertEqual(doc["events"][0]["baseline"], "proc-maps")

    def test_the_model_passes_through_what_the_kernel_reported(self):
        """The strongest check available, and it costs no extra stop.

        `cat /proc/self/maps` prints the kernel's own account of the address
        space at the moment it read the file.  Replaying the deltas has to
        produce exactly that layout at some point along the way.
        """
        with tempfile.NamedTemporaryFile(suffix=".json") as out:
            printed = subprocess.run(
                [sys.executable, AS_TRACE, "record", "-o", out.name,
                 *self.flags("record"), "--", "/bin/cat", "/proc/self/maps"],
                capture_output=True, text=True)
            self.assertEqual(printed.returncode, 0, printed.stderr)
            with open(out.name) as fp:
                doc = json.load(fp)

        truth = procmaps.parse(printed.stdout)
        self.assertTrue(truth, "cat printed nothing")

        space.set_page_size(doc["page_size"])
        for state in _replay(doc):
            if procmaps.compare(state, truth)["match"]:
                return
        self.fail("no point in the timeline matches the maps the program printed")

    def test_the_way_in_is_not_in_the_output(self):
        """Neither the strace trampoline nor libdebug's bootstrap shows."""
        doc = self.record("--", "/bin/echo", "hello")
        self.assertNotIn("/bin/sh", [p["exe"] for p in doc["processes"]])
        self.assertEqual(doc["events"][0]["args"]["path"], "/bin/echo")

    def test_without_a_baseline_the_space_starts_empty(self):
        doc = self.record("--no-baseline", "--", "/bin/echo", "hello")
        self.assertNotIn("delta", doc["events"][0])
        self.assertEqual(doc["checks"], [])

    def test_a_child_gets_its_own_space(self):
        doc = self.record("--", "/bin/sh", "-c", "/bin/echo a")
        self.assertGreaterEqual(len(doc["spaces"]), 2)
        self.assertGreaterEqual(len(doc["processes"]), 2)

    def test_the_exit_code_is_reported(self):
        doc = self.record("--", "/bin/sh", "-c", "exit 3")
        self.assertEqual(doc["target"]["exit_code"], 3)

    def test_the_demo_does_everything_it_says_it_does(self):
        """The demo program is a list of things a process can do to its own
        memory; each one has to arrive in the recording as itself."""
        with tempfile.TemporaryDirectory() as where:
            demo = build_demo(where)
            if demo is None:
                self.skipTest("no C compiler to build the demo with")
            doc = self.record("--", demo)

        self.assertEqual(doc["target"]["exit_code"], 0)
        events = doc["events"]

        # fork gives the child a copy of the whole space, region for region.
        self.assertEqual(len(doc["spaces"]), 2)
        parent, live, copied = events[0]["space"], set(), None
        for event in events:
            if event.get("space_created") and event["space"] != parent:
                copied = len(event["delta"]["added"])
                break
            if event["space"] != parent:
                continue
            delta = event.get("delta") or {}
            live.difference_update(delta.get("removed", []))
            live.update(r["id"] for r in delta.get("added", []))
        self.assertEqual(copied, len(live))
        self.assertGreater(copied, 20)

        # Every kind of change the viewer draws differently.
        kinds = {e["category"] for e in events}
        self.assertLessEqual({"map", "unmap", "protect", "remap", "brk",
                              "annotate", "process"}, kinds)

        regions = [r for e in events for r in (e.get("delta") or {}).get("added", [])]
        self.assertTrue([r for r in regions if r["prot"] == "---"],
                        "the reservation should arrive with no access")
        self.assertTrue([r for r in regions if r["prot"] == "r-x"
                         and not r.get("path")],
                        "a page of the arena should end up executable")
        self.assertIn("demo arena", [r.get("name") for r in regions])
        self.assertTrue([r for r in regions if r.get("path") == demo],
                        "the program maps its own image")
        self.assertTrue([r for r in regions if r["shared"]],
                        "one mapping is shared")

        # One mremap grows where it stands, the other has to move.
        remaps = [e for e in events if e["category"] == "remap" and e.get("delta")]
        self.assertEqual(len(remaps), 2)
        moved = [e for e in remaps if e["result"] != e["args"]["old_addr"]]
        grew = [e for e in remaps if e["result"] == e["args"]["old_addr"]]
        self.assertEqual((len(grew), len(moved)), (1, 1))
        for e in remaps:
            self.assertGreater(e["args"]["new_size"], e["args"]["old_size"])

        # And the hole punched out of the middle of the arena leaves the two
        # halves behind rather than taking the whole thing.
        hole = [e for e in events if e["category"] == "unmap"
                and len(e["delta"]["added"]) == 1
                and len(e["delta"]["removed"]) == 1]
        self.assertTrue(hole, "munmap of the middle should split what was there")


class EndToEndWithLibdebug(EndToEnd):
    """The same recordings, collected by libdebug driving ptrace itself."""

    BACKEND = "libdebug"


if __name__ == "__main__":
    unittest.main()


def _replay(doc: dict):
    """Every layout the timeline goes through, the way a viewer would."""
    live: dict[str, dict] = {}
    for ev in doc["events"]:
        delta = ev.get("delta") or {}
        for ident in delta.get("removed", []):
            live.pop(ident, None)
        for region in delta.get("added", []):
            live[region["id"]] = region
        yield [_desc(r) for r in live.values()]


def _desc(region: dict) -> Desc:
    prot = region["prot"]
    return Desc(
        start=int(region["start"], 16),
        end=int(region["end"], 16),
        prot=((syscalls.PROT_READ if prot[0] == "r" else 0) |
              (syscalls.PROT_WRITE if prot[1] == "w" else 0) |
              (syscalls.PROT_EXEC if prot[2] == "x" else 0)),
        shared=region["shared"],
        path=region.get("path"),
        offset=int(region.get("offset", "0x0"), 16),
        name=region.get("name"),
        kind=region["kind"],
    )
