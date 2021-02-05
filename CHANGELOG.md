# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Support encryption flag (0x1) correctly.
- Oodle support for win32reboot archives (flag 0x8). Only available for Windows
  and Linux targets due to dependency.
- Added `agesice` example utility.

## [0.1.1]

- `agesdeice` no longer syncs data to disk, resulting in a massive performance
  boost for archives with several files.

## [0.1.0]

Initial implementation. Supports reading and writing ICE v3 and v4 archives.
