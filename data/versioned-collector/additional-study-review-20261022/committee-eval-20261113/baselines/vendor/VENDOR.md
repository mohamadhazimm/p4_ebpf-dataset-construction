# Third-party code used by the baselines

Nothing here is installed into the system or the user site. Each item sits in its own folder and is put on
`sys.path` (or run by path) only by the baseline scripts that need it.

## kitsune-py/src — official Kitsune / KitNET (MIT)

- Source: `git clone https://github.com/ymirsky/Kitsune-py.git` on 2026-11-13.
- Commit: `7c8ea51e89268d9a20399dca4bf32d663e638eb4` (2026-03-24, "Merge pull request #36 from qingtian805/master").
- Files used, unmodified (SHA-256):

| file | SHA-256 |
| --- | --- |
| FeatureExtractor.py | e0eaa2055c8a578829886977d59c913fc5bd1d340ac6423c1b20fcdcf60a89eb |
| netStat.py | e9bd3584ac40f9ba519a5b11d7a67354a7006f018bab4c69fc16d38d92540388 |
| AfterImage.py | baff6a4e490ced5c56eafdba49421b46040f9fb1b3bf268a5030aeb5cefc3836 |
| KitNET/KitNET.py | 86bd9149bb81b28970ba4916bbb93f9854f95ef818cd12a77dbb03b1f72b984f |
| KitNET/dA.py | ae60bf6af8ff6d4b588de6b0f7288e9d799eda9700683bc03456213ec592022f |
| KitNET/corClust.py | bbf46343def6d86b1088fceeb6de8c56a6d37b3b937f4e4ec4cf08982c30df27 |
| KitNET/utils.py | f11dd38fcbaff878bebc6e9abd676f17a1c0e41cbc1de57ecec27e7aeb468b72 |
| KitNET/\_\_init\_\_.py | 27237fd526a3660b9fc2f0b374c7fb401aa2dbdf21d9a9dbd4c8058efbe0f063 |
| Kitsune.py (read, not used) | 58bf0f2c1e2c89773275e82b56811eab99d805969617ce44ff0ff7830be7b56a |
| example.py (read, not used) | 59a851e66e76ef7268237b6b953741d6f003e182f2907c15e22fa298759cb516 |
| AfterImage_extrapolate.pyx (not used) | 42f89a1fc16241d4a58602bedf0e793c1ed7c0503e767deb845e99862935e492 |

- The clone also contains `mirai.zip` (the authors' sample traffic capture), the paper PDF and a figure; none is
  used or extracted.
- Runtime notes (no code change): the code uses `np.Inf`, which NumPy 2.0 removed; the scripts set the alias
  `np.Inf = np.inf` before importing it. `netStat.py` calls `pyximport.install()`, so Cython is provided in
  `pylib/`; the hook is appended after the normal importers and no `.pyx` module is imported (the pure-Python
  `AfterImage.py` is used, as in the official FeatureExtractor). The current netStat returns 100 features per packet
  (the paper's 15 "Host BW" statistics are commented out in `netStat.updateGetStats`).

## pylib — Cython 3.0.11 (Apache-2.0)

- `/usr/bin/python3 -m pip install --target ./pylib --no-deps --no-compile "Cython==3.0.11"` on 2026-11-13.
- Used only to satisfy `import pyximport` in Kitsune's netStat.py. `pyximport/pyximport.py`
  SHA-256 db7863ab1f3a6f9d09d4c2e60c1581bbf11258b8b557b0a807351838a262e682, `pyximport/_pyximport3.py`
  746cc1a206969fd788596c9367d527d6310bc61f0176649edc56f1737b5e5f83 (its `install()` creates no files).

## zeek — Zeek 9.0.1 official binary package (BSD), throughput measurement only

- Repository: the Zeek project's openSUSE Build Service repository,
  `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/` (2026-11-13).
- `download/Release` signature verified with `download/Release.key` (key fingerprint
  F9FA 0223 B56B 116C 3637 37EF 5DA5 7BDD 6DD7 85CA, "security OBS Project"; key fetched from the same site);
  `Packages` SHA-256 fe94e1bd97bac0851e9bc359e66f09e9cfb5e1891573a562c2278154237eff46 matches `Release`;
  `zeek-9.0-core_9.0.1-0_amd64.deb` SHA-256 70506fe28ab27a231c3d03d7bbe6bbe6d420dbed95f89e8398931e5bd21a16c7
  matches `Packages`.
- Extracted with `dpkg-deb -x` into `zeek/root/` (not installed); all its library dependencies were already on the
  host. `zeek/root/opt/zeek/bin/zeek` SHA-256 ff59f1a30634e817bbb11b6777ab11e36379aafdb35a45a360ca78d219510836.
  Run with `ZEEKPATH`, `ZEEK_PLUGIN_PATH` and `LD_LIBRARY_PATH` pointing into `zeek/root/opt/zeek`.
