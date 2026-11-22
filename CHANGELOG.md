# Changelog

## v0.2.0

- `SourceConfig.FloorFile` keeps the newest list's position (version and issue
  time) across a restart. Before, the floor was memory only: a restarted
  gateway took a replayed older list, still signed and unexpired, as its first.
  Proven by a test that failed on v0.1.4 (a second `Source` accepted version 4
  after version 5 had been seen by the first).
- A list with the same version as the floor but issued earlier is refused too
  (the comparison used the version alone).
- New: `Floor`, `ParseFloor`, `(*Source).Floor`, `ErrFloorNotKept` (returned
  with a good list when the file cannot be written).
- Without `FloorFile` nothing changes, apart from the same-version check.

## v0.1.4 and earlier

See the tags.
