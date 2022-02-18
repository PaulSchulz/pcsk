# PCSK

PCSK is a program that

- daemonises (cleanly), and then forks a program (which so does not need to
  do the dirty work itself)

- spawns a (non-daemonising) program, waits and re-spawns it if terminated
  (guarantees that it always runs), or

- runs a program at least every n seconds, but as often as possible
  ('anti-cron')

- can do a chroot before running a program

- can change uid/gid before running a program

- logs (with timestamp) the program starting/termination events, and optionally
  the program's stdout and/or stderr in a file

PCSK is written in C.

# Features

- Ensures clean daemonisation of the spawner process (which then
  spawns the program), and checks for common error conditions before
  forking (eg. non-existing/non-executable binary)

- Writes pidfile, and checks the pidfile (running process of itself)
  to avoid starting a new copy while the old still runs.

- Can chroot() and change uid/gid before starting the program (few
  programs can do this together; and you're going to have difficulties
  if you try it with two separate binaries).

- Can log the spawned program's start/termination (including time
  stamp, exit status and runtime) events.

- Can log the spawned program's stdout and/or stderr, with time
  stamps.

- Just one more process needed per each daemonised program (the same
  process does the logging).

- Fine-tunable algorithm to avoid excess resource utilization
  (looping) when the program dies too frequently. It can be configured
  so that it gives up and exits after a given number of unsuccessful
  tries.

- It can be made running another command before exiting when finally
  gives up. (eg. send an SMS to the administrator)

- Runs as the given user when root privileges are not needed (this uid
   can be different than the uid the spawned program runs as).

- The spawned program can signal PCSK that the it should not run any
  more (let it terminate and exit PCSK itself). (This can be achieved
  by creating a file with the given name and then exiting.)

- Can be configured to run a program effectively that must not be run
  more often than n seconds, but needs to be run as often as it is
  possible. (Starts the program again immediately after it terminated
  if n seconds elapsed since the last starting.)

# Systems

The program exensively takes use of GNU libc, and some not-so-common
I/O interfaces. It was written for a GNU/Linux system. No other ports
exist (yet?). Help is welcome, if you think that it should be
ported. ;-)

# Installation

The compilation and installing is straightforward:

1. 'cd' to the directory containing the package's source code
2. Type 'make' to compile the package.
3. Type 'make install' to install the program and other stuff.

## Compilers

Works with GCC 2.95.4. Perhaps with many others, no black magic involved. :-)

## Installation Paths

By default, installs the files under '/usr/local/bin',
'/usr/local/man', etc.  You can override it with giving the
DESTDIR=<somepath> for make, eg.:

  make install DESTDIR=/opt/pcsk/

# Homepage

http://www.nix.hu/projects/pcsk

# Download

http://www.nix.hu/downloads/pcsk/

# GitHub Repository

https://github.com/PaulSchulz/pcsk

This repository is maintained by Paul Schulz. Any queries relating to the
way that the project is hosted on GitHub should be directed here.

# Author

Author: Norbert Buchmuller <norbi@nix.hu>

Comments and bug reports are welcome.
