# The dataset's static benign programs, for a live run on PC1

66 static benign programs of the release dataset (rows of `dataset/features.csv` with category `benign`, mode
`amd64_static` or `i386_static`, no network task), each the exact binary of the dataset run, with the input
files their tasks read. Run and compare them with `live_test/static_benign/` in p4_ebpf (PC1.md Part 6).

- `bin/<execution_id>/<program>`: the binary, under its original name (some programs read their name).
- `fixtures/`: the input files, byte for byte as in the dataset run.
- `cases.tsv`: one line per case. `args` is the task's argument list as JSON, with `@ROOT@` standing for the
  folder this README is in.
- `manifest.json`: the SHA-256 of every file and each case's dataset row (`row`: its index in features.csv).

The programs are command-line tools (GNU coreutils, diffutils, gzip, m4, cpio, bzip2, brotli, lz4, ncompress,
xxHash, expat's xmlwf, sqlite3), built from Ubuntu 22.04 source packages for the study. They read their input
files and write their outputs to the working directory; none uses the network.
