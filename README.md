
==========
spawn-fcgi
==========

:thanks: Jan Kneschke, Stefan Bühler

:spawn-fcgi is from http://redmine.lighttpd.net/projects/spawn-fcgi

:abstract:
  spawn-fcgi is used to spawn monitor process.

Features
--------
- binds to IPv4/IPv6 and Unix domain sockets
- supports privilege separation: chmod/chown socket, drop to uid/gid
- supports chroot
- supports daemontools supervise

Build
=====

If ./configure is missing, run ./autogen.sh.

  ./configure
  make
  make install

Alternatively you can use the cmake build system (may not work
on every platform):

  cmake .
  make
  make install


Usage
=====

See man page.
