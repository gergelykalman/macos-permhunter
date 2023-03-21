# macos-permhunter
File permission and SIP misbehaviour hunter

# Usage:
Get help:
> ~/tools/permhunter/permhunter.py --help

Shows SIP misbehaviour (permission denied when UNIX permissions would allow):
> ~/tools/permhunter/permhunter.py --startdir / --only-sip

Show writable directories under /var/run, show no errors, don't follow links,
only check for gid 1 writability, don't match owner and other perms
> ~/tools/permhunter/permhunter.py --startdir /var/run --omit-errors --omit-links --gids 1 --omit-uid --omit-oth

Look for writable directories in ~/Library/, but omit errors and skip certain
dirs
> ~/tools/permhunter/permhunter.py --startdir /Users/USER/Library/ --omit-errors --skiplist /Users/USER/Library/Developer/Xcode /Users/USER/Library/Developer/CoreSimulator

Look for ONLY writable directories
> ~/tools/permhunter/permhunter.py --startdir /Users/USER/Library/Caches/ --match-filetypes d --skiplist /Users/USER/Library/Developer/Xcode /Users/USER/Library/Developer/CoreSimulator

