# as-trace, its viewer, and the strace it drives.
#
# There is no packaging metadata in the tree -- the tool is a script and a
# package beside it -- so this copies both into the store and wraps the
# script with an interpreter that can find them.  pyelftools is optional to
# the tool and required here: without it a recording has no ELF sections,
# which is half of what the viewer draws.

{ lib
, stdenvNoCC
, makeWrapper
, python3
, strace
, runCommand
}:

let
  python = python3.withPackages (ps: [ ps.pyelftools ]);
in
stdenvNoCC.mkDerivation (final: {
  pname = "as-trace";
  version = "1.0";

  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let name = baseNameOf path; in
      name != "__pycache__" && !lib.hasSuffix ".pyc" name && name != ".git";
  };

  nativeBuildInputs = [ makeWrapper ];

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/as-trace
    cp -r asview viewer as-trace README.md $out/libexec/as-trace/
    chmod +x $out/libexec/as-trace/as-trace

    makeWrapper ${python}/bin/python3 $out/bin/as-trace \
      --add-flags $out/libexec/as-trace/as-trace \
      --prefix PATH : ${lib.makeBinPath [ strace ]}

    runHook postInstall
  '';

  # The end-to-end tests record /bin/echo and /bin/cat, which a build sandbox
  # does not have; they skip themselves there.  Everything else -- the parser
  # and the model, driven by hand-written traces -- runs.
  passthru.tests = runCommand "as-trace-tests"
    {
      nativeBuildInputs = [ python strace ];
    } ''
    cp -r ${final.src}/{asview,viewer,tests,as-trace} .
    python3 -m unittest discover -s tests -v 2>&1 | tail -6
    touch $out
  '';

  meta = {
    description = "Record how a process's address space evolves, and watch it";
    longDescription = ''
      as-trace runs a program under strace, reads the memory-related
      syscalls back, and reconstructs the address space they describe: a
      list of regions and the exact change each syscall made to it.  The
      result is a replay, which viewer/index.html animates.
    '';
    mainProgram = "as-trace";
    platforms = lib.platforms.linux;
  };
})
