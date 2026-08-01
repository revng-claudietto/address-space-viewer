/* The animation.
 *
 * It reads the JSON `as-trace` writes: a list of events, each carrying the
 * change it made to an address space.  Replaying those deltas in order gives
 * the layout at every step, which is what the map draws.
 *
 * Addresses are hexadecimal strings in the JSON, because 0xffffffffff600000
 * does not survive a double.  They stay strings here, and every comparison
 * goes through BigInt.
 *
 * No build step, no dependencies: open index.html and drop a file on it.
 */

'use strict';

(function () {

// --------------------------------------------------------------------------
// Palette, shared with viewer.css.
// --------------------------------------------------------------------------

var BLUE = 'oklch(0.74 0.15 252)';
var SKY = 'oklch(0.83 0.11 224)';
var ORANGE = 'oklch(0.78 0.16 62)';
var EMBER = 'oklch(0.70 0.19 34)';
var SAND = 'oklch(0.86 0.13 82)';
var PALE = 'oklch(0.90 0.02 250)';
var DIM = 'oklch(0.52 0.015 250)';

// What each event is, for the badge, the log dot and the tick strip.
var KIND = {
  exec:     { c: PALE,   t: 'EXEC' },
  fork:     { c: PALE,   t: 'FORK' },
  exit:     { c: PALE,   t: 'EXIT' },
  map:      { c: BLUE,   t: 'MMAP' },
  unmap:    { c: EMBER,  t: 'MUNMAP' },
  protect:  { c: SAND,   t: 'MPROTECT' },
  remap:    { c: SKY,    t: 'MREMAP' },
  brk:      { c: ORANGE, t: 'BRK' },
  advise:   { c: DIM,    t: 'ADVISE' },
  annotate: { c: DIM,    t: 'ANNOTATE' },
  signal:   { c: EMBER,  t: 'SIGNAL' },
  other:    { c: DIM,    t: 'OTHER' }
};

// What happened to a single mapping between two steps.
var CHANGE = {
  mapped:   { c: BLUE,   t: 'MAP' },
  unmapped: { c: EMBER,  t: 'UNMAP' },
  protect:  { c: SAND,   t: 'PROT' },
  moved:    { c: SKY,    t: 'MOVE' },
  resized:  { c: ORANGE, t: 'SIZE' },
  merged:   { c: SKY,    t: 'JOIN' },
  sealed:   { c: SAND,   t: 'SEAL' },
  renamed:  { c: DIM,    t: 'NAME' }
};

var ARCH = {
  EM_X86_64: 'x86-64', EM_386: 'i386', EM_AARCH64: 'aarch64', EM_ARM: 'arm',
  EM_RISCV: 'riscv', EM_PPC64: 'ppc64', EM_S390: 's390x', EM_MIPS: 'mips',
  EM_LOONGARCH: 'loongarch'
};

var LOG_ROW = 25;          // must match --log-row in viewer.css
var MS_PER_STEP = 900;
var MAX_CHANGES = 24;      // a fork copies the lot; the list is not the point
var MAX_TICKS = 320;       // as many ticks as the scrub bar can show apart

// Which event speaks for a run of them, when one tick has to cover several.
var TICK_RANK = ['exec', 'fork', 'exit', 'signal', 'unmap', 'remap', 'protect',
                 'map', 'brk', 'annotate', 'advise', 'other'];

// --------------------------------------------------------------------------
// Small helpers.
// --------------------------------------------------------------------------

function $(id) { return document.getElementById(id); }

function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

function basename(path) {
  if (!path) return '';
  var parts = String(path).split('/');
  return parts[parts.length - 1] || String(path);
}

function shortAddr(s) {
  if (!s) return '—';
  var out = String(s).replace(/^0x0+/, '0x');
  return out === '0x' ? '0x0' : out;
}

function fmtSize(n) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  var units = [['EiB', 1152921504606846976], ['PiB', 1125899906842624],
               ['TiB', 1099511627776], ['GiB', 1073741824],
               ['MiB', 1048576], ['KiB', 1024]];
  for (var i = 0; i < units.length; i++) {
    var d = units[i][1];
    if (n >= d) {
      var v = n / d;
      var x = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
      if (x.indexOf('.') >= 0) x = x.replace(/0+$/, '').replace(/\.$/, '');
      return x + ' ' + units[i][0];
    }
  }
  return n + ' B';
}

function fmtSeconds(t) {
  if (t === null || t === undefined) return '—';
  return t.toFixed(6) + ' s';
}

function plural(n, one, many) {
  return n + ' ' + (n === 1 ? one : (many || one + 's'));
}

function pad(n, width) {
  var s = String(n);
  while (s.length < width) s = '0' + s;
  return s;
}

function big(s) {
  try { return BigInt(s); } catch (e) { return null; }
}

// ?trace=run.json loads one on arrival, &autoplay starts it moving.
function param(name) {
  return new URLSearchParams(location.search).get(name);
}

// --------------------------------------------------------------------------
// The model: events, and the layout of every address space at every step.
// --------------------------------------------------------------------------

function bucketOf(raw) {
  switch (raw.kind) {
    case 'file': case 'shm': return 'file';
    case 'vdso': case 'vvar': case 'vsyscall': case 'special':
    case 'shadow-stack': return 'special';
    default: return 'anon';
  }
}

/* The ELF sections that fall inside a mapping, biggest overlap first.  A
   section lands at `bias + addr` of the region that names the object, which
   is the whole reason as-trace reports a bias at all. */
function sectionsIn(raw, objects) {
  if (!raw.object || !raw.bias || !objects) return [];
  var obj = objects[raw.object];
  if (!obj || !obj.sections) return [];
  var bias = big(raw.bias), s = big(raw.start), e = big(raw.end);
  if (bias === null || s === null || e === null) return [];
  var out = [];
  for (var i = 0; i < obj.sections.length; i++) {
    var sec = obj.sections[i];
    if (!sec.flags || sec.flags.indexOf('A') < 0) continue;   // never mapped
    var a = big(sec.addr);
    if (a === null) continue;
    a += bias;
    var b = a + BigInt(sec.size || 0);
    if (b <= s || a >= e) continue;
    var lo = a > s ? a : s, hi = b < e ? b : e;
    out.push({ name: sec.name, overlap: Number(hi - lo) });
  }
  out.sort(function (x, y) { return y.overlap - x.overlap; });
  return out;
}

function labelOf(r) {
  if (r.name) return r.name;
  var top = r.sections.length ? r.sections[0].name : null;
  if (r.path) {
    var base = basename(r.path);
    // The first page of an ELF is its header and program headers, whatever
    // else the loader put in the same PT_LOAD.
    if (r.object && r.offset === '0x0') return base + ' ELF headers';
    return top ? base + ' ' + top : base;
  }
  if (r.object) {
    var owner = basename(r.object);
    if (top) return owner + ' ' + top;
    if (r.zero_fill) return owner + ' .bss';
    return owner;
  }
  switch (r.kind) {
    case 'heap': return '[heap]';
    case 'stack': return '[stack]';
    case 'shm': return 'shared memory';
    case 'shadow-stack': return 'shadow stack';
    default: return 'anonymous';
  }
}

function makeRegion(raw, objects) {
  var r = {};
  for (var k in raw) if (Object.prototype.hasOwnProperty.call(raw, k)) r[k] = raw[k];
  r._s = big(raw.start) || BigInt(0);
  r._e = big(raw.end) || r._s;
  r.perms = (raw.prot || '---') + (raw.shared ? 's' : 'p');
  r.blocked = r.perms.slice(0, 3) === '---';
  r.bucket = bucketOf(raw);
  r.sections = sectionsIn(raw, objects);
  r.label = labelOf(r);
  return r;
}

function kindKeyOf(ev) {
  if (ev.category === 'process') {
    var n = ev.syscall;
    if (n === 'execve' || n === 'execveat') return 'exec';
    if (n === 'fork' || n === 'vfork' || n === 'clone' || n === 'clone3') return 'fork';
    return 'exit';
  }
  return KIND[ev.category] ? ev.category : 'other';
}

/* strace prints `pid time name(args) = ret`; the JSON keeps the whole line.
   Splitting it back is nicer to read than reassembling it from `args`, and
   it is what actually ran. */
function splitRaw(ev) {
  var raw = (ev.raw || '').trim().replace(/^(\d+\s+)?\d+\.\d+\s+/, '');
  // A call another thread interrupted is two lines joined by the parser; the
  // second one carries its own pid and timestamp, which say nothing here.
  raw = raw.replace(/ \.\.\. (\d+\s+)?\d+\.\d+\s+/, ' ... ');
  var call = raw, ret = '';
  var cut = raw.lastIndexOf(' = ');
  if (cut > 0) {
    call = raw.slice(0, cut);
    ret = raw.slice(cut + 3);
  }
  if (!call) {
    call = (ev.syscall || ev.summary || '') +
      (ev.args ? '(' + JSON.stringify(ev.args).slice(1, -1) + ')' : '');
  }
  if (!ret) {
    if (ev.error) ret = '-1 ' + ev.error;
    else if (ev.result !== undefined && ev.result !== null) ret = String(ev.result);
    else ret = '—';
  }
  return { call: call, ret: ret };
}

function buildModel(doc) {
  var objects = doc.objects || {};
  var raw = doc.events || [];

  var events = raw.map(function (ev, i) {
    var e = {};
    for (var k in ev) if (Object.prototype.hasOwnProperty.call(ev, k)) e[k] = ev[k];
    var parts = splitRaw(ev);
    e.index = i;
    e.callText = parts.call;
    e.retText = parts.ret;
    e.kindKey = kindKeyOf(ev);
    e.added = [];
    return e;
  });

  // Every address space the trace mentions, in the order it first shows up.
  var ids = [], seen = {};
  function note(id) { if (id && !seen[id]) { seen[id] = true; ids.push(id); } }
  (doc.spaces || []).forEach(function (s) { note(s.id); });
  events.forEach(function (e) { note(e.space); note(e.space_created); });

  var frames = {}, extents = {}, firstSeen = {}, live = {};
  ids.forEach(function (id) {
    frames[id] = new Array(events.length);
    extents[id] = [];
    firstSeen[id] = {};
    live[id] = [];
  });

  var placed = {};                     // id@start-end, so each extent is drawn once
  events.forEach(function (ev, i) {
    var sid = ev.space;
    if (sid && frames[sid] && ev.delta) {
      var gone = {};
      (ev.delta.removed || []).forEach(function (id) { gone[id] = true; });
      var added = (ev.delta.added || []).map(function (r) {
        return makeRegion(r, objects);
      });
      ev.added = added;
      added.forEach(function (r) {
        if (!firstSeen[sid][r.id]) firstSeen[sid][r.id] = r;
        var key = sid + '/' + r.id + '@' + r.start + '-' + r.end;
        if (!placed[key]) { placed[key] = true; extents[sid].push(r); }
      });
      var next = live[sid].filter(function (r) { return !gone[r.id]; }).concat(added);
      next.sort(function (a, b) { return a._s < b._s ? -1 : a._s > b._s ? 1 : 0; });
      live[sid] = next;
    }
    ids.forEach(function (id) { frames[id][i] = live[id]; });
  });

  var model = {
    doc: doc,
    events: events,
    spaceIds: ids,
    spaces: {},
    frames: frames,
    extents: extents,
    firstSeen: firstSeen,
    layouts: {},
    _changes: new Array(events.length)
  };
  (doc.spaces || []).forEach(function (s) { model.spaces[s.id] = s; });

  model.changesAt = function (i) {
    if (this._changes[i]) return this._changes[i];
    var out = changesAt(this, i);
    this._changes[i] = out;
    return out;
  };
  return model;
}

/* What this step did to individual mappings.
 *
 * as-trace keeps a region's id only while the region is untouched, so an
 * mprotect of the middle of one drops an id and adds three.  Each new region
 * names where it came from in `origin`, and that lineage is what turns a
 * remove/add pair back into "this got protected" or "this moved". */
function changesAt(model, i) {
  var ev = model.events[i];
  var sid = ev.space;
  if (!sid || !model.frames[sid]) return [];
  var removed = (ev.delta && ev.delta.removed) || [];
  if (!ev.added.length && !removed.length) return [];

  var prev = i > 0 ? model.frames[sid][i - 1] : [];
  var before = {};
  prev.forEach(function (r) { before[r.id] = r; });

  var consumed = {}, out = [];
  ev.added.forEach(function (r) {
    var from = (r.origin || []).filter(function (id) { return before[id]; });
    from.forEach(function (id) { consumed[id] = true; });
    if (!from.length) {
      out.push({ id: r.id, type: 'mapped', label: r.label,
                 detail: fmtSize(r.size) + ' ' + r.perms });
    } else if (from.length > 1) {
      out.push({ id: r.id, type: 'merged', label: r.label,
                 detail: from.length + ' joined into one' });
    } else {
      var p = before[from[0]];
      if (p.perms !== r.perms) {
        out.push({ id: r.id, type: 'protect', label: r.label,
                   detail: p.perms + ' → ' + r.perms });
      } else if (p.start !== r.start) {
        out.push({ id: r.id, type: 'moved', label: r.label,
                   detail: shortAddr(p.start) + ' → ' + shortAddr(r.start) });
      } else if (p.size !== r.size) {
        out.push({ id: r.id, type: 'resized', label: r.label,
                   detail: fmtSize(p.size) + ' → ' + fmtSize(r.size) });
      } else if (!p.sealed !== !r.sealed) {
        out.push({ id: r.id, type: 'sealed', label: r.label,
                   detail: 'sealed against further change' });
      } else if (p.label !== r.label) {
        out.push({ id: r.id, type: 'renamed', label: r.label,
                   detail: p.label + ' → ' + r.label });
      } else {
        out.push({ id: r.id, type: 'mapped', label: r.label,
                   detail: fmtSize(r.size) + ' ' + r.perms });
      }
    }
  });
  removed.forEach(function (id) {
    if (consumed[id]) return;
    var p = before[id];
    out.push({ id: id, type: 'unmapped', label: p ? p.label : id,
               detail: p ? fmtSize(p.size) + ' released' : 'released' });
  });
  return out;
}

// --------------------------------------------------------------------------
// The address axis.
//
// Every address a region ever occupied gets room, whether or not it is
// mapped right now, so a mapping never has to jump aside to make space for
// one that appears later.  Between those, unmapped stretches are collapsed
// to a fixed height -- the distance from the heap to the stack is real but
// not interesting, and drawing it to scale leaves nothing else visible.
// --------------------------------------------------------------------------

function computeLayout(model, sid, mode, H) {
  var inst = model.extents[sid] || [];
  var bset = {}, i;
  for (i = 0; i < inst.length; i++) { bset[inst[i].start] = 1; bset[inst[i].end] = 1; }
  var bs = Object.keys(bset).sort(function (a, b) {
    var x = big(a), y = big(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  var lay = { mode: mode, H: H, pos: {}, runs: [], gaps: [], total: H };
  if (bs.length < 2) return lay;

  var at = {};
  bs.forEach(function (b, k) { at[b] = k; });
  var covered = new Array(bs.length - 1);
  for (i = 0; i < inst.length; i++) {
    for (var k = at[inst[i].start]; k < at[inst[i].end]; k++) covered[k] = true;
  }

  var linear = mode === 'linear', log = mode === 'log';
  var exp = linear ? 1 : 0.42;
  var iv = [];
  for (i = 0; i < bs.length - 1; i++) {
    var size = Number(big(bs[i + 1]) - big(bs[i]));
    var v = { addr: bs[i], next: bs[i + 1], size: size, covered: !!covered[i] };
    if (v.covered) { v.min = linear ? 3 : 22; v.w = Math.pow(size, exp); }
    else if (linear) { v.min = 2; v.w = size; }
    else if (log) { v.min = 14; v.w = Math.pow(size, exp) * 0.3; }
    else { v.min = 14 + Math.max(0, Math.min(22, Math.log2(size) - 20)); v.w = 0; }
    iv.push(v);
  }

  var minTotal = iv.reduce(function (s, v) { return s + v.min; }, 0);
  var weight = iv.reduce(function (s, v) { return s + v.w; }, 0) || 1;
  var target = Math.max(H, minTotal + (linear ? 0 : 440));
  var k2 = Math.max(0, target - minTotal) / weight;

  var y = 0, run = null;
  iv.forEach(function (v) {
    lay.pos[v.addr] = y;
    var h = v.min + v.w * k2;
    if (v.covered) {
      if (!run) { run = { top: y, start: v.addr, end: v.next, h: 0 }; lay.runs.push(run); }
      run.end = v.next;
      run.h = y + h - run.top;
    } else {
      run = null;
      lay.gaps.push({ top: y, h: h, size: v.size,
                      labeled: h >= 13 && v.size >= 1048576 });
    }
    y += h;
  });
  lay.pos[bs[bs.length - 1]] = y;
  lay.total = y;

  lay.runs.forEach(function (r) {
    var a = big(r.start), b = big(r.end), names = [];
    for (var j = 0; j < inst.length; j++) {
      var x = inst[j];
      if (x._s < a || x._e > b) continue;
      var n = x.path ? basename(x.path) : (/^\[[^\]]+\]/.exec(x.label) || [null])[0] || x.label;
      if (n && names.indexOf(n) < 0) names.push(n);
    }
    var pick = null;
    for (var m = 0; m < names.length; m++) {
      if (names[m].indexOf('.so') >= 0 || names[m][0] !== '[') { pick = names[m]; break; }
    }
    r.title = pick && names.length > 1 ? pick : names.slice(0, 2).join(' + ');
  });
  return lay;
}

// --------------------------------------------------------------------------
// State.
// --------------------------------------------------------------------------

var state = {
  model: null,
  idx: 0,
  playing: false,
  speed: 1,
  axis: 'collapsed',
  space: null,
  follow: true,
  hover: null,
  pick: null,
  height: 720,
  timer: null,
  lastIdx: -1
};

var slots = {};            // region id -> the nodes that draw it
var decor = null;          // runs and gaps, redrawn only when the axis changes
var drawnLayout = null;
var logRows = [];
var tickNodes = [];

// --------------------------------------------------------------------------
// Loading.
// --------------------------------------------------------------------------

/* A file that turns out not to be a trace should not cost you the one you
   are already looking at: the panel comes back over it, and Escape or a
   click outside puts it away again. */
function fail(message) {
  var box = $('startup-error');
  box.textContent = message;
  box.hidden = false;
  $('startup').hidden = false;
  $('startup-hint').textContent = state.model
    ? 'Escape goes back to the trace already loaded'
    : 'or open this page with ?trace=run.json';
  if (!state.model) $('hdr-cmd').textContent = 'no trace loaded';
}

function dismissStartup() {
  if (!state.model) return;
  $('startup').hidden = true;
  $('startup-error').hidden = true;
}

function load(doc, name) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.events)) {
    fail((name ? name + ': ' : '') + 'this is not an as-trace JSON file ' +
         '(no "events" array).');
    return;
  }
  if (!doc.events.length) {
    fail((name ? name + ': ' : '') + 'the trace has no events.');
    return;
  }
  if (!doc.events[0] || doc.events[0].seq === undefined) {
    fail((name ? name + ': ' : '') + 'its events are not the ones as-trace ' +
         'writes (no "seq").');
    return;
  }

  setPlaying(false);
  var model = buildModel(doc);
  state.model = model;
  state.idx = 0;
  state.lastIdx = -1;
  state.hover = null;
  state.pick = null;
  state.follow = true;
  state.space = model.events[0].space || model.spaceIds[0] || null;
  model.layouts = {};

  $('startup').hidden = true;
  $('startup-error').hidden = true;

  fillHeader(model);
  buildChips(model);
  buildLog(model);
  buildTicks(model);
  buildMarkers(model);
  buildInfo(model);
  buildSlots();
  measure();
  render();

  if (param('autoplay') !== null) setPlaying(true);
}

function loadText(text, name) {
  var doc;
  try { doc = JSON.parse(text); }
  catch (e) { fail((name ? name + ': ' : '') + 'not valid JSON — ' + e.message); return; }
  load(doc, name);
}

function loadFile(file) {
  var reader = new FileReader();
  reader.onload = function () { loadText(String(reader.result), file.name); };
  reader.onerror = function () { fail('could not read ' + file.name); };
  reader.readAsText(file);
}

function loadUrl(url) {
  fetch(url).then(function (r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.text();
  }).then(function (text) {
    loadText(text, url);
  }).catch(function (e) {
    fail('could not fetch ' + url + ' — ' + e.message +
         (location.protocol === 'file:'
           ? '. A page opened from a file cannot fetch one; drop the JSON here instead.'
           : ''));
  });
}

// --------------------------------------------------------------------------
// Header, chips, notes.
// --------------------------------------------------------------------------

function rootPid(doc) {
  var procs = doc.processes || [];
  for (var i = 0; i < procs.length; i++) {
    if (procs[i].parent === null || procs[i].parent === undefined) return procs[i].pid;
  }
  return procs.length ? procs[0].pid : null;
}

function archOf(doc) {
  var objects = doc.objects || {};
  for (var k in objects) {
    if (objects[k] && objects[k].machine) {
      return ARCH[objects[k].machine] || objects[k].machine;
    }
  }
  return '—';
}

function fillHeader(model) {
  var doc = model.doc;
  var target = doc.target || {};
  var cmd = target.argv ? target.argv.join(' ') : (target.source || '—');
  $('hdr-cmd').textContent = cmd;
  $('hdr-cmd').title = cmd;
  var pid = rootPid(doc);
  $('hdr-pid').textContent = pid === null ? '—' : pid;
  $('hdr-arch').textContent = archOf(doc);
  var gen = doc.generator || {};
  $('hdr-tool').textContent = (gen.tool || 'as-trace') +
    (gen.version ? ' ' + gen.version : '');

  var trouble = (doc.warnings || []).length +
    (doc.checks || []).filter(function (c) { return !c.match; }).length;
  var button = $('info-button');
  button.textContent = trouble ? 'INFO · ' + trouble : 'INFO';
  button.classList.toggle('warn', trouble > 0);
}

function buildChips(model) {
  var box = $('space-chips');
  box.textContent = '';
  var many = model.spaceIds.length > 1;
  box.hidden = !many;
  $('map-caption').hidden = many;
  if (!many) return;

  model.spaceIds.forEach(function (id) {
    var info = model.spaces[id] || {};
    var members = info.members || [];
    var who = info.creator !== undefined && info.creator !== null ? info.creator
      : members.length ? members[0] : null;
    var chip = el('button', 'chip', id.toUpperCase() +
      (who === null ? '' : ' · pid ' + who) +
      (members.length > 1 ? ' +' + (members.length - 1) : ''));
    chip.type = 'button';
    chip.title = (info.reason ? 'created by ' + info.reason : '') +
      (info.baseline ? ', starting layout: ' + info.baseline : '') +
      (members.length ? ', used by pid ' + members.join(', ') : '');
    chip.addEventListener('click', function () {
      state.space = id;
      state.follow = false;
      state.pick = null;
      buildSlots();
      render();
    });
    box.appendChild(chip);
    chip._space = id;
  });

  var follow = el('button', 'chip', 'FOLLOW');
  follow.type = 'button';
  follow.title = 'show whichever address space the current event acts on';
  follow.addEventListener('click', function () {
    state.follow = !state.follow;
    if (state.follow) syncSpace();
    render();
  });
  follow._follow = true;
  box.appendChild(follow);
}

function updateChips() {
  var box = $('space-chips');
  if (box.hidden) return;
  var model = state.model;
  var ev = model.events[state.idx];
  Array.prototype.forEach.call(box.children, function (chip) {
    if (chip._follow) {
      chip.classList.toggle('on', state.follow);
      return;
    }
    var info = model.spaces[chip._space] || {};
    chip.classList.toggle('on', chip._space === state.space);
    var ended = info.destroyed_by !== undefined && info.destroyed_by !== null &&
      ev.seq >= info.destroyed_by;
    var born = info.created_by === undefined || info.created_by === null ||
      ev.seq >= info.created_by;
    chip.classList.toggle('ended', ended || !born);
  });
}

/* One region of a `checks` entry, where the reconstruction and the kernel's
   own account of the same address space did not line up. */
function describeDifference(d) {
  function span(r) {
    return shortAddr(r.start) + '-' + shortAddr(r.end) + ' ' + r.prot +
      (r.shared ? 's' : 'p');
  }
  if (d.model && d.kernel) return span(d.model) + ' vs ' + span(d.kernel);
  if (d.model) return span(d.model) + ' only in the model';
  if (d.kernel) return span(d.kernel) + ' only in the kernel';
  return '';
}

function buildInfo(model) {
  var doc = model.doc;
  var body = $('info-body');
  body.textContent = '';

  function section(name) {
    body.appendChild(el('div', 'section-title', name));
    var rows = el('div', 'rows');
    body.appendChild(rows);
    return function (k, v) {
      if (v === undefined || v === null || v === '') return;
      var r = el('div', 'row');
      r.appendChild(el('span', 'k', k));
      r.appendChild(el('span', 'v', String(v)));
      rows.appendChild(r);
    };
  }

  var target = doc.target || {}, gen = doc.generator || {};
  var row = section('TARGET');
  row('command', target.argv ? target.argv.join(' ') : target.source);
  row('cwd', target.cwd);
  row('exit code', target.exit_code === null ? 'unknown' : target.exit_code);
  row('recorded', target.traced_at
    ? new Date(target.traced_at * 1000).toISOString().replace('T', ' ').slice(0, 19)
    : null);
  row('wall time', target.wall_seconds ? target.wall_seconds + ' s' : null);
  row('tool', ((gen.tool || '') + ' ' + (gen.version || '')).trim());
  row('strace', gen.strace);
  row('page size', doc.page_size);
  row('schema', doc.schema);

  row = section('ADDRESS SPACES');
  (doc.spaces || []).forEach(function (s) {
    row(s.id, s.reason + ', ' + (s.members || []).length + ' user(s), peak ' +
      s.peak_regions + ' regions / ' + fmtSize(s.peak_bytes) +
      ', starting layout ' + s.baseline);
  });
  (doc.processes || []).forEach(function (p) {
    row('pid ' + p.pid, (p.exe || '?') +
      (p.thread_of ? ' (thread of ' + p.thread_of + ')' : '') +
      (p.exit ? ' — ' + p.exit : ''));
  });

  var checks = doc.checks || [], warnings = doc.warnings || [];
  if (checks.length) {
    body.appendChild(el('div', 'section-title', 'CHECKED AGAINST THE KERNEL'));
    checks.forEach(function (c) {
      var item = el('div', 'note-item' + (c.match ? ' ok' : ''));
      item.appendChild(el('span', 'bullet', c.match ? '✓' : '!'));
      var text = el('span');
      var jump = el('span', 'jump', 'event ' + c.at_event);
      jump.addEventListener('click', function () { go(indexOfSeq(c.at_event)); });
      text.appendChild(jump);
      var said = c.match
        ? ': the reconstruction is what /proc/' + c.pid + '/maps says it is.'
        : ': ' + plural(c.differences.length, 'region') +
          ' differ from /proc/' + c.pid + '/maps — ' +
          c.differences.slice(0, 4).map(describeDifference).join('; ');
      text.appendChild(document.createTextNode(' (' + c.space + ')' + said));
      item.appendChild(text);
      body.appendChild(item);
    });
  }
  if (warnings.length) {
    body.appendChild(el('div', 'section-title', 'WARNINGS'));
    warnings.forEach(function (w) {
      var item = el('div', 'note-item');
      item.appendChild(el('span', 'bullet', '!'));
      item.appendChild(el('span', null, w));
      body.appendChild(item);
    });
  }
}

function indexOfSeq(seq) {
  var events = state.model.events;
  for (var i = 0; i < events.length; i++) if (events[i].seq === seq) return i;
  return Math.max(0, Math.min(events.length - 1, seq));
}

// --------------------------------------------------------------------------
// The trace log and the scrub bar.
// --------------------------------------------------------------------------

function buildLog(model) {
  var box = $('log-scroll');
  box.textContent = '';
  logRows = [];
  var many = model.spaceIds.length > 1;

  model.events.forEach(function (ev, i) {
    var row = el('div', 'log-row');
    row.appendChild(el('span', 'seq', pad(ev.seq, 2)));
    var dot = el('span', 'dot');
    row.appendChild(dot);
    row.appendChild(el('span', 'text', ev.summary || ev.syscall || ''));
    if (many) row.appendChild(el('span', 'where', ev.space || ''));
    row.title = ev.callText;
    row.addEventListener('click', function () { go(i); });
    box.appendChild(row);
    logRows.push({ row: row, dot: dot, colour: (KIND[ev.kindKey] || KIND.other).c });
  });
  $('log-count').textContent = model.events.length;
}

/* One tick per event, until there are more events than the strip has room
   for; past that a tick stands for a run of them, so the bar keeps meaning
   "how far along you are" rather than quietly dropping the tail. */
function buildTicks(model) {
  var box = $('ticks');
  box.textContent = '';
  tickNodes = [];

  var n = model.events.length;
  var per = Math.ceil(n / MAX_TICKS);
  box.style.gap = per > 1 || n > 240 ? '1px' : '2px';

  for (var from = 0; from < n; from += per) {
    var to = Math.min(n, from + per);
    var pick = model.events[from];
    for (var i = from; i < to; i++) {
      if (TICK_RANK.indexOf(model.events[i].kindKey) <
          TICK_RANK.indexOf(pick.kindKey)) pick = model.events[i];
    }
    var tick = el('span', 'tick');
    tick.title = per === 1 ? pick.seq + '  ' + (pick.summary || '')
      : 'events ' + model.events[from].seq + '–' + model.events[to - 1].seq;
    tick.addEventListener('click', (function (at) {
      return function () { go(at); };
    })(from));
    box.appendChild(tick);
    tickNodes.push({ node: tick, colour: (KIND[pick.kindKey] || KIND.other).c,
                     from: from, to: to });
  }
}

function updateTicks() {
  tickNodes.forEach(function (t) {
    var on = state.idx >= t.from && state.idx < t.to;
    var past = state.idx >= t.to;
    t.node.className = 'tick' + (on ? ' on' : past ? ' past' : '');
    t.node.style.background = on || past ? t.colour : '#232a30';
  });
}

/* The labels under the scrub bar: the moments worth naming, at the place in
   the trace where they happened. */
function buildMarkers(model) {
  var box = $('markers');
  box.textContent = '';
  var n = model.events.length;
  var wanted = [];
  model.events.forEach(function (ev, i) {
    if (ev.kindKey === 'exec' && ev.ok !== false) {
      wanted.push({ i: i, rank: 0, label: 'execve ' + basename((ev.args || {}).path || '') });
    } else if (ev.kindKey === 'exit') {
      wanted.push({ i: i, rank: 1, label: ev.syscall || 'exited' });
    } else if (ev.kindKey === 'signal') {
      wanted.push({ i: i, rank: 2, label: (ev.args || {}).signal || 'signal' });
    } else if (ev.kindKey === 'fork') {
      wanted.push({ i: i, rank: 3, label: ev.syscall });
    }
  });

  // Keep the important ones, and never two labels on top of each other.
  wanted.sort(function (a, b) { return a.rank - b.rank || a.i - b.i; });
  var kept = [];
  wanted.forEach(function (m) {
    if (kept.length >= 7) return;
    for (var j = 0; j < kept.length; j++) {
      if (Math.abs(kept[j].i - m.i) / n < 0.07) return;
    }
    kept.push(m);
  });
  kept.sort(function (a, b) { return a.i - b.i; });

  if (kept.length < 2) {
    var last = model.events[n - 1];
    kept = [{ i: 0, label: 't = 0' },
            { i: n - 1, label: last.t !== null && last.t !== undefined
                ? last.t.toFixed(3) + ' s' : 'end' }];
  }

  kept.forEach(function (m) {
    var node = el('span', 'marker', m.label);
    var pct = n > 1 ? (m.i + 0.5) / n * 100 : 50;
    if (pct < 8) { node.style.left = '0'; }
    else if (pct > 92) { node.style.right = '0'; }
    else {
      node.style.left = pct.toFixed(2) + '%';
      node.style.transform = 'translateX(-50%)';
    }
    node.addEventListener('click', function () { go(m.i); });
    box.appendChild(node);
  });
}

function updateLog() {
  var idx = state.idx, last = state.lastIdx;
  var lo = last < 0 ? 0 : Math.max(0, Math.min(idx, last) - 1);
  var hi = last < 0 ? logRows.length - 1 : Math.min(logRows.length - 1, Math.max(idx, last) + 1);
  for (var i = lo; i <= hi; i++) {
    var r = logRows[i];
    var on = i === idx, past = i < idx;
    r.row.className = 'log-row' + (on ? ' on' : past ? ' past' : '');
    r.row.style.borderLeftColor = on ? r.colour : 'transparent';
    r.dot.style.background = on || past ? r.colour : '#2b3238';
  }
  if (idx !== last) {
    var box = $('log-scroll');
    var want = idx * LOG_ROW - box.clientHeight / 2 + LOG_ROW / 2;
    box.scrollTop = Math.max(0, want);
  }
}

// --------------------------------------------------------------------------
// The map.
// --------------------------------------------------------------------------

function layoutFor(sid) {
  var key = sid + '|' + state.axis + '|' + state.height;
  var cache = state.model.layouts;
  if (!cache[key]) {
    cache[key] = computeLayout(state.model, sid, state.axis, state.height);
  }
  return cache[key];
}

function buildSlots() {
  var canvas = $('map-canvas');
  canvas.textContent = '';
  slots = {};
  drawnLayout = null;

  decor = el('div');
  decor.style.cssText = 'position:absolute;inset:0;';
  canvas.appendChild(decor);

  var first = state.model.firstSeen[state.space] || {};
  Object.keys(first).forEach(function (id) {
    var slot = el('div', 'slot');
    var box = el('div', 'box');
    var hatch = el('span', 'hatch');
    var label = el('span', 'box-label');
    var meta = el('span', 'box-meta');
    var perms = el('span', 'box-perms');
    var size = el('span', 'box-size');
    meta.appendChild(perms);
    meta.appendChild(size);
    box.appendChild(hatch);
    box.appendChild(label);
    box.appendChild(meta);
    slot.appendChild(box);
    box.addEventListener('click', function () {
      state.pick = state.pick === id ? null : id;
      updateMap();
      renderDetail();
    });
    box.addEventListener('mouseenter', function () {
      state.hover = id;
      updateMap();
      renderDetail();
    });
    box.addEventListener('mouseleave', function () {
      if (state.hover !== id) return;
      state.hover = null;
      updateMap();
      renderDetail();
    });
    canvas.appendChild(slot);
    slots[id] = { slot: slot, box: box, hatch: hatch, label: label,
                  perms: perms, size: size, shown: null };
  });
}

function drawDecor(lay) {
  decor.textContent = '';
  lay.gaps.forEach(function (g) {
    var node = el('div', 'gap');
    node.style.top = g.top + 'px';
    node.style.height = g.h + 'px';
    node.appendChild(el('span', 'dashes'));
    if (g.labeled) {
      node.appendChild(el('span', 'gap-label', fmtSize(g.size) + ' unmapped'));
      node.appendChild(el('span', 'dashes'));
    }
    decor.appendChild(node);
  });
  lay.runs.forEach(function (r) {
    var tall = r.h >= 34;
    var node = el('div', 'run');
    node.style.top = r.top + 'px';
    node.style.height = r.h + 'px';
    node.appendChild(el('span', 'rail'));
    node.appendChild(el('span', 'addr top', shortAddr(r.start)));
    var title = el('span', 'run-title', r.title || '');
    title.style.fontSize = (tall ? 11 : 10) + 'px';
    if (r.h < 20) title.style.opacity = '0';
    node.appendChild(title);
    var bottom = el('span', 'addr bottom', shortAddr(r.end));
    if (!tall) bottom.style.opacity = '0';
    node.appendChild(bottom);
    decor.appendChild(node);
  });
}

function updateMap() {
  var model = state.model, sid = state.space;
  if (!sid || !model.frames[sid]) return;
  var lay = layoutFor(sid);
  if (lay !== drawnLayout) {
    drawnLayout = lay;
    $('map-canvas').style.height = Math.round(lay.total) + 'px';
    drawDecor(lay);
  }

  var frames = model.frames[sid];
  var cur = frames[state.idx];
  var prev = state.idx > 0 ? frames[state.idx - 1] : [];
  var byId = {}, wasById = {};
  cur.forEach(function (r) { byId[r.id] = r; });
  prev.forEach(function (r) { wasById[r.id] = r; });

  var marks = {};
  if (model.events[state.idx].space === sid) {
    model.changesAt(state.idx).forEach(function (c) { marks[c.id] = c.type; });
  }

  var joinAbove = {}, joinBelow = {};
  cur.forEach(function (r, i) {
    var p = cur[i - 1], n = cur[i + 1];
    if (p && p.end === r.start) joinAbove[r.id] = true;
    if (n && n.start === r.end) joinBelow[r.id] = true;
  });

  var picked = state.hover || state.pick;
  var first = model.firstSeen[sid];
  var totalBytes = 0;

  Object.keys(slots).forEach(function (id) {
    var node = slots[id];
    var liveHere = byId[id];
    var r = liveHere || wasById[id] || first[id];
    if (liveHere && !r.blocked) totalBytes += r.size;

    var top = lay.pos[r.start] || 0;
    var bottom = lay.pos[r.end];
    var h = Math.max(6, (bottom === undefined ? top : bottom) - top);
    node.slot.style.top = top + 'px';
    node.slot.style.height = h + 'px';

    var mark = marks[id];
    node.slot.className = 'slot' + (liveHere ? '' : ' absent') +
      (picked === id ? ' picked' : mark ? ' changed' : '');

    var radius = h < 15 ? 5 : 11;
    var above = joinAbove[id] ? 0 : radius, below = joinBelow[id] ? 0 : radius;
    node.box.className = 'box ' + (r.blocked ? 'none' : r.bucket) +
      (joinAbove[id] ? ' joined-above' : '') + (h < 15 ? ' squat' : '');
    node.box.style.borderRadius = above + 'px ' + above + 'px ' +
      below + 'px ' + below + 'px';
    node.box.style.fontSize = (h < 19 ? 10 : 11.5) + 'px';
    node.box.style.boxShadow = mark
      ? 'inset 0 0 0 1px ' + CHANGE[mark].c + ', 0 0 24px -4px ' + CHANGE[mark].c
      : picked === id ? 'inset 0 0 0 1px #8a97a4' : 'none';

    if (node.shown !== r) {
      node.shown = r;
      node.label.textContent = r.label;
      node.perms.textContent = r.perms;
      node.perms.className = 'box-perms' + (r.perms[1] === 'w' ? ' writable' : '');
      node.size.textContent = fmtSize(r.size);
      node.hatch.className = 'hatch' +
        (r.blocked ? ' blocked' : r.perms[2] === 'x' ? ' exec' : '');
    }
  });

  var info = model.spaces[sid] || {};
  var ended = info.destroyed_by !== undefined && info.destroyed_by !== null &&
    model.events[state.idx].seq >= info.destroyed_by;
  $('map-counts').textContent = cur.length + ' MAPPINGS · ' +
    fmtSize(totalBytes) + ' MAPPED' + (ended ? ' · SPACE ENDED' : '');
}

// --------------------------------------------------------------------------
// The event panel.
// --------------------------------------------------------------------------

function regionAt(frame, addr) {
  var v = big(addr);
  if (v === null) return null;
  for (var i = 0; i < frame.length; i++) {
    if (frame[i]._s <= v && v < frame[i]._e) return frame[i];
  }
  return null;
}

/* A sentence about this step, in terms of what it did rather than what it
   was called.  Everything here comes out of the record; nothing is guessed. */
function noteFor(i) {
  var model = state.model, ev = model.events[i];
  var args = ev.args || {};
  var changes = model.changesAt(i);
  var frame = ev.space && model.frames[ev.space] ? model.frames[ev.space][i] : [];
  var bits = [];

  function count(type) {
    return changes.filter(function (c) { return c.type === type; }).length;
  }
  var wasN = (ev.delta && ev.delta.removed) ? ev.delta.removed.length : 0;
  var nowN = ev.added.length;

  if (ev.ok === false) {
    bits.push('The call failed with ' + (ev.error || 'an error') +
              ', so the address space is exactly as it was.');
  } else if (ev.kindKey === 'exec') {
    if (ev.baseline === 'proc-maps') {
      bits.push('execve threw the old address space away and built this one. ' +
        'The ' + ev.added.length + ' regions are /proc/' + ev.pid + '/maps, read ' +
        'while the process was held after the call returned and before the first ' +
        'instruction of ' + (args.path || 'the program') + ' ran: no syscall ' +
        'reports any of this.');
    } else {
      bits.push('execve threw the old address space away and built a new one, ' +
        'which nothing read. The map starts empty and fills in as the loader ' +
        'maps what it needs.');
    }
  } else if (ev.kindKey === 'fork') {
    if (args.shares_space) {
      bits.push(ev.syscall + ' made ' + args.child + ' another user of this same ' +
        'address space: nothing was copied, and anything either one maps from ' +
        'now on both of them see.');
    } else {
      bits.push(args.child + ' got a copy of the address space — ' +
        ev.added.length + ' regions at the same addresses, private to it from ' +
        'now on. The pages themselves are shared until one side writes.');
    }
  } else if (ev.kindKey === 'exit') {
    bits.push(ev.summary + '.');
    if (ev.space_destroyed && ev.space_destroyed.length) {
      bits.push('That was the last user of ' + ev.space_destroyed.join(', ') +
        '; the layout shown is what it held when it went.');
    }
  } else if (ev.category === 'map') {
    var what = args.path
      ? 'a window on ' + basename(args.path) +
        (args.offset && args.offset !== '0x0' ? ' from offset ' + args.offset : '')
      : 'anonymous memory, which is zero until something writes to it';
    bits.push(ev.syscall + ' returned ' + shortAddr(ev.result) + ': ' +
      fmtSize(args.length) + ' of ' + what + '.');
    if (count('unmapped')) {
      bits.push('It landed on ' + plural(count('unmapped'), 'mapping') +
        ' that were already there, which it replaced.');
    }
    if (count('merged')) {
      bits.push('The kernel folded it into the mapping beside it: same ' +
        'permissions, same backing, so there is one VMA where the trace shows ' +
        'two calls.');
    }
  } else if (ev.category === 'unmap') {
    bits.push('munmap released ' + fmtSize(args.length) + ' at ' +
      shortAddr(args.addr) + '.');
    if (count('unmapped')) {
      bits.push(plural(count('unmapped'), 'mapping') + ' went with it.');
    }
    if (count('resized')) {
      bits.push(plural(count('resized'), 'other was', 'others were') + ' trimmed.');
    }
  } else if (ev.category === 'protect') {
    var became = changes.filter(function (c) { return c.type === 'protect'; });
    bits.push(ev.syscall + ' set ' + (args.prot || '') + ' on ' +
      fmtSize(args.length) + ' at ' + shortAddr(args.addr) +
      (became.length ? ' (' + became[0].detail + ')' : '') + '.');
    if (nowN > wasN) {
      bits.push('It covered part of a region: where there ' + plural(wasN, 'was', 'were') +
        ' there are now ' + nowN + ', because one VMA cannot hold two sets of ' +
        'permissions.');
    } else if (count('merged')) {
      bits.push('The new permissions match the mapping next to it, so the kernel ' +
        'folded them into a single VMA.');
    }
  } else if (ev.category === 'remap') {
    bits.push(ev.summary + '.');
    var move = changes.filter(function (c) { return c.type === 'moved'; })[0];
    if (move) {
      bits.push('mremap moves the page tables, not the bytes: the contents are ' +
        'at ' + shortAddr(ev.result) + ' without having been copied.');
    }
  } else if (ev.category === 'brk') {
    var heap = null;
    for (var h = 0; h < frame.length; h++) if (frame[h].kind === 'heap') heap = frame[h];
    if (args.addr === '0x0' || args.addr === 'NULL') {
      bits.push('A read of the break: this is where the heap would start growing, ' +
        'not a change to it.');
    } else if (heap) {
      bits.push('The break moved to ' + shortAddr(ev.result) + ', leaving a heap of ' +
        fmtSize(heap.size) + '. malloc asks for this when its own arena runs out.');
    } else {
      bits.push('The break moved to ' + shortAddr(ev.result) + '.');
    }
  } else if (ev.category === 'advise') {
    bits.push(ev.summary + '. The mapping stays exactly as it is; only what the ' +
      'kernel does with the pages behind it changes.');
  } else if (ev.category === 'annotate') {
    bits.push(ev.summary + '.');
  } else if (ev.category === 'signal') {
    var where = args.si_addr ? regionAt(frame, args.si_addr) : null;
    bits.push(ev.summary + '.');
    if (args.si_addr) {
      bits.push(where
        ? shortAddr(args.si_addr) + ' is inside ' + where.label + ', which is ' +
          where.perms + '.'
        : shortAddr(args.si_addr) + ' is in none of the mappings above.');
    }
  } else {
    bits.push(ev.summary + '.');
  }

  if (ev.delayed && ev.kindKey === 'exec') {
    bits.push('strace held the process here so its map could be read; the pause ' +
      'is taken back out of t.');
  }
  return bits.join(' ');
}

function renderEvent() {
  var model = state.model, ev = model.events[state.idx];
  var kind = KIND[ev.kindKey] || KIND.other;

  $('ev-seq').textContent = pad(ev.seq, 2) + ' / ' +
    pad(model.events[model.events.length - 1].seq, 2);
  $('ev-time').textContent = fmtSeconds(ev.t);
  $('ev-time').title = ev.t_wall !== undefined
    ? 'measured at ' + fmtSeconds(ev.t_wall) + ', with our own pause taken out'
    : '';

  var badge = $('ev-kind');
  badge.textContent = kind.t;
  badge.style.color = kind.c;
  badge.style.borderColor = kind.c;

  var tag = $('ev-space');
  tag.hidden = model.spaceIds.length < 2;
  tag.textContent = (ev.space || '') + ' · pid ' + ev.pid;

  var m = /^([a-z_0-9]+)(\(.*)$/.exec(ev.callText);
  $('ev-name').textContent = m ? m[1] : ev.callText;
  $('ev-args').textContent = m ? m[2] : '';
  var ret = $('ev-ret');
  ret.textContent = ev.retText;
  ret.className = 'ret' + (ev.ok === false ? ' failed' : '');

  $('ev-note').textContent = noteFor(state.idx);

  var box = $('ev-changes');
  box.textContent = '';
  var changes = ev.space === state.space ? model.changesAt(state.idx) : [];
  if (!changes.length) {
    var quiet = el('div', 'change quiet');
    quiet.appendChild(el('span', null, ev.space === state.space
      ? 'no change to the map'
      : 'this event acts on ' + ev.space + ', not on the space shown'));
    box.appendChild(quiet);
  }
  changes.slice(0, MAX_CHANGES).forEach(function (c) {
    var style = CHANGE[c.type];
    var row = el('div', 'change');
    var tagNode = el('span', 'tag', style.t);
    tagNode.style.color = style.c;
    row.appendChild(tagNode);
    row.appendChild(el('span', 'what', c.label));
    row.appendChild(el('span', 'detail', c.detail));
    row.addEventListener('mouseenter', function () {
      state.hover = c.id; updateMap(); renderDetail();
    });
    row.addEventListener('mouseleave', function () {
      if (state.hover !== c.id) return;
      state.hover = null; updateMap(); renderDetail();
    });
    box.appendChild(row);
  });
  if (changes.length > MAX_CHANGES) {
    var more = el('div', 'change quiet');
    more.appendChild(el('span', null,
      'and ' + (changes.length - MAX_CHANGES) + ' more'));
    box.appendChild(more);
  }
}

function renderDetail() {
  var model = state.model, sid = state.space;
  var id = state.hover || state.pick;
  var rows = $('detail-rows');
  rows.textContent = '';

  function row(k, v) {
    var node = el('div', 'row');
    node.appendChild(el('span', 'k', k));
    node.appendChild(el('span', 'v', v));
    rows.appendChild(node);
  }

  if (!id) {
    $('detail-title').textContent = 'MAPPING';
    row('', 'Hover or click a mapping for its details.');
    return;
  }

  var frames = model.frames[sid];
  var cur = frames[state.idx];
  var live = null, was = null, i;
  for (i = 0; i < cur.length; i++) if (cur[i].id === id) live = cur[i];
  if (!live && state.idx > 0) {
    var prev = frames[state.idx - 1];
    for (i = 0; i < prev.length; i++) if (prev[i].id === id) was = prev[i];
  }
  var r = live || was || model.firstSeen[sid][id];
  if (!r) { $('detail-title').textContent = 'MAPPING'; return; }

  $('detail-title').textContent = 'MAPPING · ' + r.label.toUpperCase();
  row('start', r.start);
  row('end', r.end);
  row('size', fmtSize(r.size) + '  (' +
    (state.model.doc.page_size ? r.size / state.model.doc.page_size : '?') + ' pages)');
  row('perms', r.perms + '   ' +
    (r.perms[0] === 'r' ? 'read ' : '') + (r.perms[1] === 'w' ? 'write ' : '') +
    (r.perms[2] === 'x' ? 'exec ' : '') + (r.blocked ? 'no access ' : '') +
    (r.perms[3] === 'p' ? '· private' : '· shared'));
  row('backing', r.bucket === 'file' ? 'file'
    : r.bucket === 'special' ? 'kernel-managed'
    : r.zero_fill ? 'anonymous (a PT_LOAD’s .bss)'
    : 'anonymous (zero-fill)');
  row('path', r.path || '—');
  if (r.path) row('offset', r.offset);
  if (r.object && r.object !== r.path) row('object', r.object);
  if (r.bias) row('bias', r.bias);
  if (r.sections && r.sections.length) {
    row('sections', r.sections.map(function (s) { return s.name; }).join(' '));
  }
  if (r.flags && r.flags.length) row('flags', r.flags.join(' '));
  if (r.sealed) row('sealed', 'yes — mseal, cannot be changed again');
  row('since', 'event ' + r.since + (r.origin ? ', from ' + r.origin.join(' ') : ''));
  row('live', live ? 'mapped at this step'
    : 'not mapped at this step — its place is kept so nothing else moves');
}

// --------------------------------------------------------------------------
// Playback.
// --------------------------------------------------------------------------

function syncSpace() {
  var ev = state.model.events[state.idx];
  if (state.follow && ev.space && state.model.frames[ev.space] &&
      ev.space !== state.space) {
    state.space = ev.space;
    state.pick = null;
    state.hover = null;
    buildSlots();
  }
}

function render() {
  if (!state.model) return;
  syncSpace();
  updateChips();
  updateMap();
  renderEvent();
  renderDetail();
  updateLog();
  updateTicks();

  var last = state.model.events.length - 1;
  $('counter-text').textContent = pad(state.idx, 2) + '/' + last;
  $('btn-first').disabled = state.idx === 0;
  $('btn-prev').disabled = state.idx === 0;
  $('btn-next').disabled = state.idx === last;
  $('btn-last').disabled = state.idx === last;
  state.lastIdx = state.idx;
}

function go(i) {
  if (!state.model) return;
  var last = state.model.events.length - 1;
  state.idx = Math.max(0, Math.min(last, i));
  render();
}

function step(d) {
  setPlaying(false);
  go(state.idx + d);
}

function setPlaying(on) {
  state.playing = on;
  clearInterval(state.timer);
  state.timer = null;
  var button = $('btn-play');
  button.textContent = on ? 'II' : '▶';
  button.classList.toggle('playing', on);
  if (!on || !state.model) return;
  state.timer = setInterval(function () {
    if (state.idx >= state.model.events.length - 1) { setPlaying(false); return; }
    go(state.idx + 1);
  }, MS_PER_STEP / state.speed);
}

function buildSpeeds() {
  var box = $('speeds');
  box.textContent = '';
  [0.5, 1, 2, 4].forEach(function (v) {
    var button = el('button', v === state.speed ? 'on' : '', v + '×');
    button.type = 'button';
    button.addEventListener('click', function () {
      state.speed = v;
      Array.prototype.forEach.call(box.children, function (b) {
        b.classList.toggle('on', b === button);
      });
      if (state.playing) setPlaying(true);
    });
    box.appendChild(button);
  });
}

// --------------------------------------------------------------------------
// Wiring.
// --------------------------------------------------------------------------

function measure() {
  var box = $('map-scroll');
  var h = Math.max(380, Math.round(box.clientHeight) - 32);
  if (Math.abs(h - state.height) <= 2) return false;
  state.height = h;
  return true;
}

function start() {
  buildSpeeds();

  $('btn-first').addEventListener('click', function () { setPlaying(false); go(0); });
  $('btn-prev').addEventListener('click', function () { step(-1); });
  $('btn-next').addEventListener('click', function () { step(1); });
  $('btn-last').addEventListener('click', function () {
    setPlaying(false);
    go(state.model ? state.model.events.length - 1 : 0);
  });
  $('btn-play').addEventListener('click', function () {
    if (!state.model) return;
    if (!state.playing && state.idx >= state.model.events.length - 1) go(0);
    setPlaying(!state.playing);
  });

  Array.prototype.forEach.call($('axis-seg').children, function (button) {
    button.addEventListener('click', function () {
      state.axis = button.dataset.mode;
      Array.prototype.forEach.call($('axis-seg').children, function (b) {
        b.classList.toggle('on', b === button);
      });
      if (state.model) render();
    });
  });

  $('open-button').addEventListener('click', function () { $('file-input').click(); });
  $('startup-button').addEventListener('click', function () { $('file-input').click(); });
  $('file-input').addEventListener('change', function () {
    if (this.files && this.files[0]) loadFile(this.files[0]);
    this.value = '';
  });

  var panel = $('info-panel');
  $('info-button').addEventListener('click', function () {
    if (!state.model) return;
    panel.hidden = !panel.hidden;
  });
  $('info-close').addEventListener('click', function () { panel.hidden = true; });

  $('startup').addEventListener('click', function (e) {
    if (e.target === $('startup')) dismissStartup();
  });

  document.addEventListener('keydown', function (e) {
    // A focused button already answers to Space and Enter on its own.
    if (e.target && /^(INPUT|TEXTAREA|BUTTON)$/.test(e.target.tagName)) return;
    if (e.key === 'ArrowRight') { step(1); e.preventDefault(); }
    else if (e.key === 'ArrowLeft') { step(-1); e.preventDefault(); }
    else if (e.key === 'Home') { setPlaying(false); go(0); e.preventDefault(); }
    else if (e.key === 'End' && state.model) {
      setPlaying(false); go(state.model.events.length - 1); e.preventDefault();
    } else if (e.key === ' ') {
      if (state.model) setPlaying(!state.playing);
      e.preventDefault();
    } else if (e.key === 'Escape') { panel.hidden = true; dismissStartup(); }
  });

  var mask = $('dropmask');
  var depth = 0;
  window.addEventListener('dragenter', function (e) {
    e.preventDefault();
    depth++;
    if (state.model) mask.hidden = false;
  });
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('dragleave', function (e) {
    e.preventDefault();
    if (--depth <= 0) { depth = 0; mask.hidden = true; }
  });
  window.addEventListener('drop', function (e) {
    e.preventDefault();
    depth = 0;
    mask.hidden = true;
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files[0]) loadFile(files[0]);
  });

  if (typeof ResizeObserver !== 'undefined') {
    var observer = new ResizeObserver(function () {
      if (measure() && state.model) render();
    });
    observer.observe($('map-scroll'));
  } else {
    window.addEventListener('resize', function () {
      if (measure() && state.model) render();
    });
  }

  var url = param('trace');
  if (url) loadUrl(url);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}

})();
