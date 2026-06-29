#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import sys
if sys.version_info < (PYTHON_MIN := (3, 12)):
    raise SystemExit(f"ERROR: python {PYTHON_MIN[0]}.{PYTHON_MIN[1]} or newer required")

import platform
if platform.system() not in ('Darwin', 'FreeBSD'):
    raise SystemExit("ERROR: paranoid requires macOS or FreeBSD (st_birthtime unavailable on this platform)")

import os
import json
import time
import shutil
import hashlib
import argparse
import fnmatch
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pprint import pprint
from pathlib import Path
import multiprocessing

__version__ = "1.0.0"

@dataclass(frozen=True, slots=True)
class HashedFile:
    st_size     : int
    st_birthtime: int
    st_mtime    : int
    hash_deep   : str | None
    hash_time   : str

NEW_STR      = "✨ NEW     : "
DELETED_STR  = "🗑️  DELETED : "
CHANGED_STR  = "✏️  CHANGED : "
CORRUPT_STR  = "🪱 SUSPECT : "
METADATA_STR = "🕰️  METADATA: "
DUPE_STR     = "👯 DUPES   : "

def live_hash_file(_searchpath_file: tuple[Path, str]) -> tuple[str, HashedFile]:
    (_searchpath, _relfile) = _searchpath_file

    with (_searchpath / _relfile).open('rb') as f:
        st = os.fstat(f.fileno())
        hash_deep = f"sha256:{hashlib.file_digest(f, hashlib.sha256).hexdigest()}"

        # re-stat to detect concurrent modification
        st2 = os.fstat(f.fileno())
        if (st2.st_mtime != st.st_mtime) or (st2.st_size != st.st_size):
            raise RuntimeError(f"file modified during hashing: '{_relfile}'; try again")

        return (
            _relfile,
            HashedFile(
                st.st_size,
                int(st.st_birthtime),
                int(st.st_mtime),
                hash_deep,
                datetime.now(timezone.utc)
                    .isoformat(timespec='seconds') # don't use microseconds
                    .replace('+00:00', 'Z') # Z: shorthand for UTC timezone, requires python 3.11
            )
        )

def live_hash_files(
    _searchpath: Path,
    _relfiles: list[str],
    _serial: bool,
    ) -> dict[str, HashedFile]:
    total_file_size = 0
    start_wall_time = time.perf_counter()

    CLEAR_STATUS_LINE = "\r\033[2K" # \r -> go to column 0, \033[2K -> clear the whole line
    STATUS_MAX_WIDTH = max(0, shutil.get_terminal_size(fallback=(120, 20)).columns - 2)

    # get the hashes and file size of every file
    hashes_live = {}
    with multiprocessing.Pool(processes=1 if _serial else 3) as pool: # diminishing returns after parallel 3
        try:
            pool_tasks = [(_searchpath, f) for f in _relfiles]

            jobs_total = len(pool_tasks)
            jobs_done  = 0

            # uncoupling the iterator instantiation from the loop forces worker failures to trigger inside the try block, preventing unhandled hangs
            result_iterator = pool.imap_unordered(live_hash_file, pool_tasks, chunksize=1)
            for (hf_name, hf) in result_iterator:
                jobs_done += 1

                # print status
                BAR_PENDING_CHAR = '░'
                BAR_DONE_CHAR = '▓'
                BAR_NUM = 20
                bar_done = int(BAR_NUM * jobs_done / jobs_total)
                progress_bar = f"[{BAR_DONE_CHAR * bar_done}{BAR_PENDING_CHAR * (BAR_NUM - bar_done)}]"

                status = f"{progress_bar} ({jobs_done}/{jobs_total}): {hf_name}"
                status = status[:STATUS_MAX_WIDTH] # truncate the line

                if hf_name.isascii():
                    # unicode filenames mess up the status display
                    print(f"{CLEAR_STATUS_LINE}{status}", end="", flush=True) # clear the whole line, no newline

                hashes_live[hf_name] = hf # HashedFile

                total_file_size += hf.st_size
        except (KeyboardInterrupt, Exception):
            pool.terminate()
            pool.join()
            raise

    # clear out last printed line
    print(CLEAR_STATUS_LINE, end='', flush=True)

    if hashes_live:
        print(f"Deep-hashed {len(hashes_live):,} files ({total_file_size/2**30:.1f} GiB) @ {(total_file_size/(time.perf_counter()-start_wall_time))/2**20:,.1f} MiB/s")

    return hashes_live

HASHFILE_NAME   = '__paranoid__.json'

def hashfile_path(_searchpath: Path) -> Path:
    return _searchpath / HASHFILE_NAME

def superhash(_hashed_files: dict[str, HashedFile]) -> str:
    # hash the hashdict itself
    h = hashlib.sha256()
    for k in sorted(_hashed_files):
        hf = _hashed_files[k]
        h.update(
            # null (\0) is the only byte forbidden in filenames on every major filesystem, so this separator will never appear inside a field
            ('\0'.join(str(v) for v in [k, *asdict(hf).values()]) + '\0')
            .encode()
        )

    return f"sha256:{h.hexdigest()}"

SUPERHASH_JSON_ELEMENT = '\x00superhash\x00'

def save_hashdict(_searchpath: Path, _hashed_files: dict[str, HashedFile]) -> None:
    if any(hf.hash_deep is None or hf.hash_deep == '' for hf in _hashed_files.values()):
        raise RuntimeError("attempting to save dictionary with empty deep hashes") # we never save empty deep hashes

    dict_j = {k: asdict(v) for k, v in _hashed_files.items()} # create dict from HashedFile's
    # add superhash of dict
    dict_j[SUPERHASH_JSON_ELEMENT] = superhash(_hashed_files)

    with (tmp_path := hashfile_path(_searchpath).with_suffix('.tmp')).open('w') as f:
        json.dump(
            dict_j,
            f,
            indent=4,
            sort_keys=True,
            ensure_ascii=False # sort lexographically for diffs, allow unicode characters
        )
        f.write('\n') # trailing newline
        # ensure file is written prior to replace()
        f.flush()
        os.fsync(f.fileno())
    tmp_path.replace(hashfile_path(_searchpath)) # atomic

    # fsync parent directory to persist the new directory entry
    dir_fd = os.open(str(hashfile_path(_searchpath).parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

    print(f"Saved dictionary '{hashfile_path(_searchpath)}'")

def load_hashdict(_searchpath: Path) -> dict[str, HashedFile] | None:
    if not hashfile_path(_searchpath).is_file(): # does the dictionary file exist already?
        return None

    print(f"Loading dictionary '{hashfile_path(_searchpath)}'...")
    with hashfile_path(_searchpath).open('r') as f:
        try:
            j = json.load(f)
            if not isinstance(j, dict):
                raise TypeError

            # remove superhash of dict first
            superhash_value = j.pop(SUPERHASH_JSON_ELEMENT) # KeyError if missing
            hashed_files = {k: HashedFile(**v) for k, v in j.items()} # ** unpacking 'splat' operator unpacks a dict into keyword arguments
        except (KeyError, AttributeError, TypeError, json.JSONDecodeError):
            raise SystemExit(f"ERROR: dictionary '{hashfile_path(_searchpath)}' could not be parsed; delete it manually and try again")

    if superhash_value != superhash(hashed_files):
        raise SystemExit(f"ERROR: dictionary '{hashfile_path(_searchpath)}' failed integrity check; delete it manually and try again")

    return hashed_files

IGNOREFILE_NAME = '.paranoid_ignore'

def ignore_file(
    _f_test: Path,
    _dir_ignore_patterns: dict[Path, list[str]],
    _args: argparse.Namespace,
    ) -> bool:
    SPECIAL_FILES = frozenset({HASHFILE_NAME})
    SPECIAL_DIRS  = frozenset()

    if platform.system() == 'Darwin': # macOS
        SPECIAL_FILES |= frozenset({'.DS_Store', 'Thumbs.db', '.localized'})
        SPECIAL_DIRS  |= frozenset({'.fseventsd', '.Spotlight-V100', '.TemporaryItems', '.Trashes'})

    # filter special files
    if _f_test.name in SPECIAL_FILES:
        return True

    for _f_test_ancestor in _f_test.parents:
        # filter special directory parents
        if _f_test_ancestor.name in SPECIAL_DIRS:
            return True

        ignore_patterns = _dir_ignore_patterns.get(_f_test_ancestor)
        if not ignore_patterns:
            continue

        rel = _f_test.relative_to(_f_test_ancestor)
        for i_p in ignore_patterns:
            if i_p.endswith('/'): # directory pattern
                i_ps = i_p.rstrip('/')
                if '/' in i_ps:
                    # multi-component directory name pattern: match against path prefixes
                    for depth in range(1, len(rel.parts)):
                        rel_prefix = '/'.join(rel.parts[:depth])
                        if fnmatch.fnmatch(rel_prefix, i_ps):
                            if _args.verbose:
                                print(f"Ignoring '{str(_f_test)}' (directory pattern '{i_p}' from '{_f_test_ancestor / IGNOREFILE_NAME}')")
                            return True
                else:
                    # simple directory name pattern: match against individual components
                    for f_dir_part in rel.parts[:-1]:
                        if fnmatch.fnmatch(f_dir_part, i_ps):
                            if _args.verbose:
                                print(f"Ignoring '{str(_f_test)}' (directory pattern '{i_p}' from '{_f_test_ancestor / IGNOREFILE_NAME}')")
                            return True
            elif '/' in i_p: # relative file name pattern (pattern contains '/' but doesn't end with '/'): match against path relative to ignore file's directory
                if fnmatch.fnmatch('/'.join(rel.parts), i_p):
                    if _args.verbose:
                        print(f"Ignoring '{str(_f_test)}' (relative pattern '{i_p}' from '{_f_test_ancestor / IGNOREFILE_NAME}')")
                    return True
            else:
                # file name pattern
                if fnmatch.fnmatch(_f_test.name, i_p):
                    if _args.verbose:
                        print(f"Ignoring '{str(_f_test)}' (file pattern '{i_p}' from '{_f_test_ancestor / IGNOREFILE_NAME}')")
                    return True

    return False

def list_files(_searchpath: Path, _args: argparse.Namespace) -> list[str]:
    files = []
    dir_ignore_patterns = {}

    # pathlib.Path.rglob() does not follow symlinks for recursive directory traversal.
    # this behavior was implemented to prevent issues like infinite loops when dealing with circular symlinks.
    print(f"Listing files in {_searchpath}...")
    for f in _searchpath.rglob('*'):
        if f.is_symlink() or not f.is_file():
            pass # ignore directories, symlinks, and non-regular files
        elif f.name == IGNOREFILE_NAME:
            if _args.verbose:
                print(f"Loading ignore file '{str(f)}'")

            with f.open('r') as i:
                for line_p in i:
                    line_p = line_p.strip()
                    if line_p and not line_p.startswith('#'): # if not an empty line or a comment
                        dir_ignore_patterns.setdefault(
                            f.parent, # the ignorefile's directory location
                            []        # the ignorefile's list of patterns
                        ).append(line_p)
        else:
            files.append(f)

    # filter ignored files by matching directories with ignore patterns
    if dir_ignore_patterns:
        print(f"Processing ignore files...")

    # Path.as_posix() returns deterministic path across OSes, always gives forward slashes, unlike str(Path)
    return [
        f.relative_to(_searchpath).as_posix() # do not include searchpath
        for f in sorted(files) if not ignore_file(f, dir_ignore_patterns, _args)
    ]

def ago_from_iso8601(_ts: str) -> str:
    _ts = datetime.fromisoformat(_ts)
    now = datetime.now(timezone.utc)

    seconds = int((now - _ts).total_seconds())

    days    = seconds // 86400
    hours   = seconds // 3600
    minutes = seconds // 60

    if (value := days // 365):
        unit = "year"
    elif (value := days // 31):
        unit = "month"
    elif (value := days // 7):
        unit = "week"
    elif (value := days):
        unit = "day"
    elif (value := hours):
        unit = "hour"
    elif (value := minutes):
        unit = "minute"
    else:
        value = seconds
        unit = "second"

    return f"{value} {unit}{'s' if value != 1 else ''} ago"

OFFSET_TAB = ' '*13 # aligns with filename after emoji category prefix
GROUP_INDENT_CHAR = '▶'

def yn_save(_args: argparse.Namespace) -> bool:
    print()
    yn = 'n' if _args.dry_run else ''
    while yn not in ['y', 'n']:
        yn = input('Update? (y/n): ').lower()
    return yn == 'y'

def work_quick(_searchpath: Path, _hashes_saved: dict[str, HashedFile] | None, _args: argparse.Namespace) -> bool:
    if _hashes_saved is None:
        return work(_searchpath, None, _args)

    # get all files in searchpath
    files_live = list_files(_searchpath, _args)

    print_lines = []

    fileset_new     = set(files_live) - _hashes_saved.keys() # files we haven't seen before
    for f in sorted(fileset_new):
        print_lines.append(f"{NEW_STR}{_searchpath / f}")

    fileset_deleted = _hashes_saved.keys() - set(files_live) # files we don't see anymore
    for f in sorted(fileset_deleted):
        print_lines.append(f"{DELETED_STR}{_searchpath / f}")
        if _args.verbose:
            print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hashed {ago_from_iso8601(_hashes_saved[f].hash_time)}")

    fileset_qchanged = set()
    for f in sorted(set(files_live) & set(_hashes_saved)):
        fs_l = (_searchpath / f).stat()

        # live fingerprint doesn't match saved fingerprint
        if (_hashes_saved[f].st_size, _hashes_saved[f].st_mtime) != (fs_l.st_size, int(fs_l.st_mtime)):
            print_lines.append(f"{CHANGED_STR}{_searchpath / f}")
            if _args.verbose:
                print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hashed {ago_from_iso8601(_hashes_saved[f].hash_time)}")
            fileset_qchanged.add(f)

    quick_changes_str = "quick changes (size + modification time)"

    if not (fileset_new or fileset_deleted or fileset_qchanged):
        print(f"No {quick_changes_str} found")
        return False # no changes

    print(f"\n{quick_changes_str}\n---\n{'\n'.join(print_lines)}")

    if yn_save(_args):
        # prune deleted hashes
        for f in fileset_deleted:
            _hashes_saved.pop(f)

        # take snapshot to restore old hash_times
        hashes_saved_old = dict(_hashes_saved)

        # update new/qchanged files
        _hashes_saved |= live_hash_files(_searchpath, sorted(fileset_new | fileset_qchanged), _args.serial)

        # preserve the earliest hash_time if the hash hasn't changed
        for f in hashes_saved_old:
            if _hashes_saved[f].hash_deep == hashes_saved_old[f].hash_deep:
                _hashes_saved[f] = HashedFile(
                    _hashes_saved[f].st_size,
                    _hashes_saved[f].st_birthtime,
                    _hashes_saved[f].st_mtime,
                    _hashes_saved[f].hash_deep,
                    hashes_saved_old[f].hash_time # re-use old hash_time
                )

        save_hashdict(_searchpath, _hashes_saved)

    return True

def work(_searchpath: Path, _hashes_saved: dict[str, HashedFile] | None, _args: argparse.Namespace) -> bool:
    # get all files in searchpath
    files_live = list_files(_searchpath, _args)

    # live hashes
    hashes_live = live_hash_files(_searchpath, files_live, _args.serial) # keys are Path.as_posix()

    if _hashes_saved is None:
        # saved hashfile does not exist, create it from hashes_live
        if not _args.dry_run:
            save_hashdict(_searchpath, hashes_live)

        return False # no changes

    fileset_changed = set()
    fileset_corrupt = set()
    fileset_meta    = set()
    for f in set(hashes_live) & set(_hashes_saved):
        if _hashes_saved[f].hash_deep != hashes_live[f].hash_deep:
            # live hash doesn't match saved hash
            if _hashes_saved[f].st_mtime == hashes_live[f].st_mtime:
                # modification time is still the same, this could indicate corruption
                # simulate a corrupt file by changing contents and restoring original mtime:
                # 1. stat -f "%m" <file>
                # 2. edit <file>
                # 3. touch -t $(date -r <original_mtime> +%Y%m%d%H%M.%S) <file>
                fileset_corrupt.add(f)
            else:
                fileset_changed.add(f)
        else:
            # live hash matches saved hash...
            if _hashes_saved[f].st_birthtime != hashes_live[f].st_birthtime:
                # ...but st_birthtime doesn't match, this indicates timestamp tampering
                fileset_meta.add(f)
            elif _hashes_saved[f].st_mtime != hashes_live[f].st_mtime:
                # ...but st_mtime doesn't match, file was touched
                fileset_meta.add(f)

    fileset_new     = hashes_live.keys() - _hashes_saved.keys()
    fileset_deleted = _hashes_saved.keys() - hashes_live.keys()

    print_lines = []

    # NEW
    for f in sorted(fileset_new):
        print_lines.append(f"{NEW_STR}{_searchpath / f}")
    # DELETED
    for f in sorted(fileset_deleted):
        print_lines.append(f"{DELETED_STR}{_searchpath / f}")
        if _args.verbose:
            print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hashed {ago_from_iso8601(_hashes_saved[f].hash_time)}")
    # CHANGED
    for f in sorted(fileset_changed):
        print_lines.append(f"{CHANGED_STR}{_searchpath / f}")
        if _args.verbose:
            print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hashed {ago_from_iso8601(_hashes_saved[f].hash_time)}")
    # META
    for f in sorted(fileset_meta):
        print_lines.append(f"{METADATA_STR}{_searchpath / f}")
        if _args.verbose:
            print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hashed {ago_from_iso8601(_hashes_saved[f].hash_time)}")
    # CORRUPT
    for f in sorted(fileset_corrupt):
        print_lines.append(f"{CORRUPT_STR}{_searchpath / f}")
        # always show, even if not --verbose
        print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hashed {ago_from_iso8601(_hashes_saved[f].hash_time)}")
        print_lines.append(f"{OFFSET_TAB}{GROUP_INDENT_CHAR} hash changed but mtime unchanged — possible file corruption")

    # list dupe groups by deep hash
    # DUPES
    num_dupes = 0
    live_deephashes = {}
    for (f, h) in hashes_live.items():
        # ignore empty files as dupes, these are common
        if h.st_size == 0: continue
        live_deephashes.setdefault(h.hash_deep, []).append(f)

    for h in live_deephashes:
        h_files = live_deephashes[h]
        if len(h_files) > 1:
            num_dupes += len(h_files) - 1 # don't count the original, only dupes
            if _args.verbose: # only print listing in verbose mode
                print_lines.append(f"{DUPE_STR}{_searchpath / h_files[0]}") # original file
                for f in h_files[1:]: # all dupe files
                    print_lines.append(f"{OFFSET_TAB}{_searchpath / f}")

    if print_lines:
        print('\nchanges\n---\n' + '\n'.join(print_lines))

    print_summary = []
    # corrupt
    if fileset_corrupt or _args.verbose: print_summary.append(f"{CORRUPT_STR}{len(fileset_corrupt)}")
    # updated
    if fileset_changed or _args.verbose: print_summary.append(f"{CHANGED_STR}{len(fileset_changed)}")
    # meta
    if fileset_meta    or _args.verbose: print_summary.append(f"{METADATA_STR}{len(fileset_meta)}")
    # new
    if fileset_new     or _args.verbose: print_summary.append(f"{NEW_STR}{len(fileset_new)}")
    # deleted
    if fileset_deleted or _args.verbose: print_summary.append(f"{DELETED_STR}{len(fileset_deleted)}")
    # dupes
    if                    _args.verbose: print_summary.append(f"{DUPE_STR}{str(num_dupes)}")

    # summary is shown in verbose output or if there are changes
    if print_summary:
        print('\nsummary\n---\n' + '\n'.join(print_summary))

    if (fileset_new or fileset_deleted or fileset_changed or fileset_meta or fileset_corrupt):
        if not yn_save(_args):
            return True # changes

        # hashes_live contains all files with deep hashes
        # preserve the earliest hash_time if the hash hasn't changed
        hashes_saved_old = _hashes_saved
        _hashes_saved     = hashes_live

        for f in hashes_saved_old:
            if f in _hashes_saved:
                if _hashes_saved[f].hash_deep == hashes_saved_old[f].hash_deep:
                    _hashes_saved[f] = HashedFile(
                        _hashes_saved[f].st_size,
                        _hashes_saved[f].st_birthtime,
                        _hashes_saved[f].st_mtime,
                        _hashes_saved[f].hash_deep,
                        hashes_saved_old[f].hash_time # re-use old hash_time
                    )

        # save hash file
        save_hashdict(_searchpath, _hashes_saved)

        return True # changes
    else:
        print("\n✅ No tracked file changes")

        return False # no changes

def main() -> int:
    parser = argparse.ArgumentParser(
        prog='paranoid',
        description=
    f"""Tracks and detects file changes in a directory tree.

Examples:
  paranoid Photos/    # first run creates the dictionary file '{HASHFILE_NAME}'
  paranoid Photos/    # subsequent runs detect changes
""",
        epilog=
    f"""
Files are tracked in {HASHFILE_NAME} in the top-level directory.

Certain files or directories can be ignored using '{IGNOREFILE_NAME}' files.
'{IGNOREFILE_NAME}' uses .gitignore-style simple pattern matching:
    *.pyc         file pattern      - matches filename anywhere in the tree
    .git/         directory pattern - matches any directory by name (trailing /)
    build/*.log   relative pattern  - matches relative to the '{IGNOREFILE_NAME}' location
    # comment     ignored
""",
    formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('paths',           type=Path,           help='paths to verify', nargs='+')
    parser.add_argument('-s', '--serial',  action="store_true", help="use serial processing (for I/O-bound external drives)")
    parser.add_argument('-d', '--dry-run', action="store_true", help="do not create or update dictionary file")
    parser.add_argument('-q', '--quick',   action="store_true", help="use metadata fingerprints (size + modification time)")
    parser.add_argument('-v', '--verbose', action="store_true", help="increase verbosity (includes dupe detection)")
    parser.add_argument('--version',       action='version',    version=f'%(prog)s {__version__}') # (prog) = argparse's placeholder for program name
    args = parser.parse_args()

    for p in args.paths:
        rp = p.resolve()

        if not rp.is_dir():
            parser.error(f"'{p}' must be a directory")

        if rp.parent != Path.cwd().resolve():
            parser.error(f"run this script from the parent directory of '{p}'")

    caffeinate() # everything up till here will be re-executed but is idempotent

    multipath = len(args.paths) > 1
    if multipath:
        args.dry_run = True # don't write hashfiles for multi-path arguments
        print("--dry-run used automatically for multi-path runs")

    ret_changes = False
    for p in args.paths:
        if multipath:
            print(f"== {p} ==")

        hashes_saved = load_hashdict(p)
        if args.quick:
            ret_changes = work_quick(p, hashes_saved, args) or ret_changes # work() always runs because it is evaluated first
        else:
            ret_changes = work      (p, hashes_saved, args) or ret_changes # work() always runs because it is evaluated first

    return 1 if ret_changes else 0 # exit_code

def caffeinate() -> None:
    CAFFEINATED = 'PARANOID_CAFFEINATED'
    if CAFFEINATED not in os.environ:
        os.environ[CAFFEINATED] = "1"
        os.execvp("caffeinate", ["caffeinate", sys.executable] + sys.argv) # this replaces the current process, so the code below doesn't run in this first process

if __name__ == '__main__':
    import signal

    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('interrupted')
        sys.exit(128 + signal.SIGINT) # exit_code = 128 + SIGINT, standard Unix exit code convention for interrupt signals
