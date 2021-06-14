# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0]

- Added new error enums for the library API (group iteration, etc). For reading,
  `DecompressError`, `LoadError`, `GroupIterError`, `AsciiError`. For writing,
  `IceWriterError`, `CompressError`.
- Significantly improved error messaging in example utilities, leveraging the
  new error types.

## [0.2.1]

Note: ICEv3 output is currently broken (and probably has always been). There
is also a previously unknown field of PRS compressed archives that needs to be
properly set and occassionally causes crashes in the game, depending on where
the ICE is used.

- Fixed output size calculation of ICE v3 when compression is turned off.
- Fixed encryption of ICE v3 when compression is turned off.
- Fixed padding of compressed groups.
- Fixed creation of header for compressed ICEv4 archives.
- Fixed creation of Oodle compressed archives.

## [0.2.0]

This release redesigns the API to be a bit more flexible and add some new
features based on research done for NGS.

- Support encryption flag (0x1) correctly.
- Oodle support for NGS archives (flag 0x8). Only available for Windows and
  Linux targets due to dependency (needs changes upstream).
- Added `agesice` example utility for packing ICE files.
- `agesice` allows optional compression (PRS and Oodle) and encryption.
- Loading archives now decrypts immediately and stores the group data in-memory.
- The slice representing each group can be obtained directly from the
  `IceArchive` with new function `group_data`. This slice is provided as-is,
  and may need to be decompressed.
- Removed `IceArchive::iter_group`, replaced by `IceGroupIter`.

## [0.1.1]

- `agesdeice` no longer syncs data to disk, resulting in a massive performance
  boost for archives with several files.

## [0.1.0]

Initial implementation. Supports reading and writing ICE v3 and v4 archives.
