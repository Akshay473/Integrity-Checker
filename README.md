# Log Integrity Checker

A small, self-contained tool for recording SHA-256 baselines of log files and
directories and detecting changes against those baselines. It provides a command
line interface and a local web interface from a single code file.

The tool uses only the Python standard library. It does not send file contents or
hashes anywhere. It is a standalone project and does not depend on, import from,
or modify any other repository on this system.

## Requirements

- Python 3.9 or newer
- macOS, Linux, or Windows

## Install

The tool is a single executable file:

```bash
chmod +x app.py
```

To use the command name from the examples:

```bash
ln -s app.py integrity-check
```

On Windows, use `python app.py` in place of `./integrity-check`.

## Quick start

Just pass a file or directory — the tool figures out what to do:

```bash
# First run: no baseline exists yet → creates one automatically
./integrity-check /var/log/syslog

# Second run: baseline exists → checks for changes
./integrity-check /var/log/syslog

# Works the same for a whole directory
./integrity-check /var/log
```

Example output:

```text
$ ./integrity-check /var/log/syslog
No baseline found. Creating one now...
Baseline created.
Path:         /var/log/syslog
Files hashed: 1
Store:        /Users/name/Library/Application Support/log-integrity

$ ./integrity-check /var/log/syslog
Status: Unmodified
Baseline: /var/log/syslog
Files checked: 1

$ ./integrity-check /var/log/syslog   # after the file is modified
Status: Modified (Hash mismatch)
Baseline: /var/log/syslog
Files checked: 1
Summary: 1 modified, 0 missing, 0 new, 0 unreadable
  MODIFIED  /var/log/syslog - SHA-256 hash does not match the baseline.
Warning: possible file tampering detected. Review the files listed above.
```

For machine-readable output, add `--json`:

```bash
./integrity-check /var/log/syslog --json
```

## Commands

The simplest usage is to pass a path directly — no subcommand needed:

```bash
./integrity-check PATH [--json] [--store DIR]
```

The tool automatically initializes a baseline on the first run and checks it on
every subsequent run.

Advanced subcommands are also available when you need more control:

| Command | Purpose |
| --- | --- |
| `PATH` *(no subcommand)* | Auto-init on first use, auto-check on all later runs. |
| `init PATH` | Explicitly create a new baseline. Refuses to overwrite unless `--force` is supplied. |
| `check PATH` | Explicitly compare a file or directory against the stored baseline. |
| `update PATH` | Accept the current state of a file or directory as trusted and write it to the baseline. |
| `reinit PATH` | Replace an existing baseline for the path. Same as `init PATH --force`. |
| `serve` | Start the local web interface. |

Global options:

| Option | Description |
| --- | --- |
| `--store DIR` | Use a specific baseline store directory. |
| `--json` | Print the check report as JSON (simple mode and `check` subcommand). |
| `--version` | Print the tool version. |

## Behaviour

- Paths are converted to their real absolute path before being stored.
- Directory operations are recursive and include all regular files.
- Symbolic link entries inside a directory are skipped rather than followed.
- Hashing is streamed, so large log files are not loaded into memory.
- A file that changes while it is being read is retried and then reported as an
  error instead of being given a misleading hash.
- New files, missing files, unreadable files, and hash mismatches are all reported.
- `update` replaces the stored state for the selected path only. Updating a
  directory also records new files under that directory and removes baseline
  entries for files that no longer exist there.
- Re-initialization discards the old baseline for the selected path and records
  the current state as the new baseline.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Baseline operation succeeded, or the check found no discrepancies. |
| `1` | The check found a modified, missing, or new file. |
| `2` | The command could not complete, or a check had unreadable files. |

## Baseline storage

The default store location is:

- macOS: `~/Library/Application Support/log-integrity`
- Linux: `$XDG_STATE_HOME/log-integrity`, falling back to
  `~/.local/state/log-integrity`
- Windows: `%LOCALAPPDATA%\\log-integrity`

Set `INTEGRITY_CHECK_STORE` or pass `--store` to use another location. A useful
choice is a separate, access-controlled volume rather than the disk that holds
the logs.

The store and its manifest files are created with owner-only permissions on
POSIX systems (`0700` for the directory, `0600` for manifests). Writes are
atomic and guarded by a file lock.

## Web interface

Start the local interface:

```bash
./app.py serve
```

Open `http://127.0.0.1:8765/`.

Options:

```bash
./app.py serve --host 127.0.0.1 --port 8765
./app.py serve --store /secure/log-integrity
```

The interface can initialize, check, update, and re-initialize baselines. It uses
no external fonts, scripts, images, or analytics. Requests carry a per-process
request token, and the default bind address is loopback only.

Binding to a non-loopback address exposes the tool to other machines on the
network. Only do that when the surrounding network and host access controls are
appropriate.

## JSON output

```bash
./integrity-check check /var/log/syslog --json
```

The report includes the checked target, baseline path, algorithm, counts, and a
result record for each file. Exit codes are unchanged.

## Security model and limitations

This tool detects changes between a stored baseline and the current file state.
It does not make logs immutable, does not prevent an attacker from modifying
files, and does not provide a remote audit trail.

The baseline is protected by filesystem permissions, not by a remote trust anchor.
Anyone who can write to the baseline store as the same operating-system user can
also replace the baseline. For stronger guarantees, keep the baseline store on a
separate system, write it to read-only media after review, or record the manifest
digest in an external append-only system.

Logs that are actively being written will legitimately differ from their baseline.
Run checks against rotated or otherwise stable files when possible.

Hash comparison proves that the file content differs from the recorded content.
It does not identify who changed the file or why.

## Project layout

| File | Purpose |
| --- | --- |
| `app.py` | Complete CLI, baseline store, hashing logic, and web interface. |
| `README.md` | This document. |
| `.gitignore` | Keeps Python cache and virtual environment files out of version control. |
