#!/usr/bin/python3

import sys
import os
import stat
import argparse

DEBUG = False


def myscandir(root, depth=0, omit_links=False, skiplist=None):
    # NOTE: We do this because os.walk silently swallows PermissionError, but we want to see them.
    if skiplist is not None:
        skip = False
        for i in skiplist:
            if root.startswith(i.rstrip("/")):
                skip = True
                break
        if skip:
            return None

    try:
        dirlist = os.listdir(root)
    except PermissionError:
        # decide if this is a true PermissionError or SIP (or smth else)
        yield PermissionError(root)
        return None

    for i in dirlist:
        fpath = os.path.join(root, i)
        # NOTE: we check for islink first, as islink() and isdir() can both be true, and we do NOT want
        #       to follow links (infinite recursion)
        if os.path.islink(fpath):
            if omit_links:
                continue
            pass
        elif os.path.isdir(fpath):
            for j in myscandir(fpath, depth=depth+1, omit_links=omit_links, skiplist=skiplist):
                yield j
            continue
        elif os.path.isfile(fpath):
            pass
        else:
            pass
        yield fpath


def permcheck(st, uids, gids, uidcheck, gidcheck, othcheck):
    uid = st.st_uid
    gid = st.st_gid
    mode = st.st_mode

    ret = set()

    if uidcheck is not None:
        if uid in uids:
            if mode & uidcheck > 0:
                ret.add("uid")
    if gidcheck is not None:
        if gid in gids:
            if mode & gidcheck > 0:
                ret.add("gid")
    if othcheck is not None:
        if mode & othcheck > 0:
            ret.add("oth")

    return ret


def main(startdir, uids, gids, omit_uid, omit_gid, omit_oth, only_sip, omit_sip, omit_errors, omit_links, skiplist):
    # set defaults if not specified
    if uids is None:
        uids = [os.getuid()]
    else:
        uids = list(map(int, uids))
    if gids is None:
        gids = os.getgroups()
    else:
        gids = list(map(int, gids))

    uid_check, gid_check, oth_check = stat.S_IWUSR, stat.S_IWGRP, stat.S_IWOTH
    if omit_uid:
        uid_check = None
    if omit_gid:
        gid_check = None
    if omit_oth:
        oth_check = None

    dirgen = myscandir(startdir, omit_links=omit_links, skiplist=skiplist)
    for i in dirgen:
        # check for error
        if type(i) is PermissionError:
            fname = i.args[0]
            try:
                st = os.stat(fname)
            except Exception as exc:
                print("ERROR: stat received an exception: {}".format(exc))
                continue

            if os.path.isdir(fname):
                ftype = "dir"
                ucheck, gcheck, ocheck = stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH
            else:
                ftype = "file"
                ucheck, gcheck, ocheck = stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH
            ret = permcheck(st, uids, gids, ucheck, gcheck, ocheck)
            if len(ret) > 0:
                if not omit_sip:
                    print("SIP ERROR: {} -> PermissionError received but {} is readable: {}".format(fname, ftype, ret))
            else:
                # error was justified, file is not readable/executable by us!
                pass

            continue

        # path is returned, good to go
        try:
            st = os.stat(i)
        except FileNotFoundError:
            # dangling link?
            if DEBUG:
                print("NOT FOUND: {}".format(i))
            continue
        except Exception as exc:
            if not omit_errors:
                print("ERROR", i, exc)
        else:
            if DEBUG:
                print("Permcheck Debug:", i, st.st_uid, st.st_gid, st.st_mode, uids, gids, uid_check, gid_check,
                      oth_check)

            ret = permcheck(st, uids, gids, uid_check, gid_check, oth_check)

            if DEBUG:
                msg = "{} has mode {}".format(i, st.st_mode)
                if "uid" in ret:
                    print("{} and is writable by uid {}".format(msg, st.st_uid))
                if "gid" in ret:
                    print("{} and is writable by gid {}".format(msg, st.st_gid))
                if "oth" in ret:
                    print("{} and is writable by everyone".format(msg))

            if len(ret) > 0:
                if not os.access(i, os.W_OK):
                    print("SIP ERROR: {} -> NOT actually writable (ret: {}, uid: {}, gid: {}, mode: {})".format(
                        i, ret, st.st_uid, st.st_gid, st.st_mode))
                else:
                    # do not display if only SIP is interesting to us
                    if not only_sip:
                        print("{} is writable (ret: {}, uid: {}, gid: {}, mode: {})".format(
                        i, ret, st.st_uid, st.st_gid, st.st_mode))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="File permission query tool")
    parser.add_argument("--startdir", type=str, required=True, help="Directory to start at")
    parser.add_argument("--only-sip", default=False, action="store_true", help="Only print SIP-related misbehaviour")
    parser.add_argument("--omit-sip", default=False, action="store_true", help="Do not print SIP-related misbehaviour")
    parser.add_argument("--omit-errors", default=False, action="store_true",
                        help="Do not print PermissionError error messages (still prints unexpected errors!)")
    parser.add_argument("--omit-links", default=False, action="store_true",
                        help="Omit symlinks from permission checks (reduce noise)")
    parser.add_argument("--skiplist", type=str, default=None, nargs="*",
                        help="Skip these directories")
    parser.add_argument("--uids", type=str, default=None, nargs="*",
                        help="UIDs to check for owner check (default: current uid)")
    parser.add_argument("--gids", type=str, default=None, nargs="*",
                        help="GIDs to check for owner check (default: current groups)")
    parser.add_argument("--omit-uid", default=False, action="store_true", help="Don't match uid")
    parser.add_argument("--omit-gid", default=False, action="store_true", help="Don't match gid")
    parser.add_argument("--omit-oth", default=False, action="store_true", help="Don't match oth(er)")

    args = parser.parse_args()

    startdir = args.startdir
    only_sip = args.only_sip
    omit_sip = args.omit_sip
    omit_errors = args.omit_errors
    omit_links = args.omit_links
    skiplist = args.skiplist
    uids = args.uids
    gids = args.gids
    omit_uid = args.omit_uid
    omit_gid = args.omit_gid
    omit_oth = args.omit_oth
    main(startdir, uids, gids, omit_uid, omit_gid, omit_oth, only_sip, omit_errors, omit_sip, omit_links, skiplist)
