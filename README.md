###  Tox Pidgin Protocol Plugin

This is a [Tox](http://tox.im) plugin for [Pidgin](http://pidgin.im).

The development is still in the very early stages and while some things work,
the plugin is not complete and might be unstable.

### Current status

As mentioned above, this is a very early stage of development so don't expect
too much. It's also my very first libpurple protocol plugin and my first time
with glib, so I'm sure I messed up a thing or two or even more. :>

Here's a screenshot of a Tox chat in Pidgin:
![Screenshot of a Tox chat in Pidgin](http://www.deadlock.dhs.org/jin/tox/tox-pidgin.png "Screenshot of a Tox chat in Pidgin")

Below is a list of things that are implemented (which does not mean they are not
buggy and won't crash and burn):

## Implemented

* adding buddies
* accepting/ignoring incoming buddy requests
* showing remote buddy status changes
* sending and receiving messages
* storing/loading Tox messenger data
* handling status changes
* setting status messages
* setting your own nickname

## Limitations

Right now you can only have one Tox account, trying to set up more will lead to
desaster, because the Tox library does not support multiple instances.
Also, if you disable and enable the account again - you will be in troubles,
because the Tox library does not support shutdown and re-initilization.

## TODO
* improve the code, integration of the Tox lib is not really ideal

### Compiling on Linux

## Overview

The build system assumes that you compile against a libtoxcore shared library
which is not part of the official Tox project. Rather, I maintain a fork of
Tox with autotools based build scripts and a libtool shared library setup.

On one hand this allows me to avoid the pain that I usually suffer with cmake,
on the other hand it allows me to develop the plugin without being stopped by
API breakage of the Tox library which may happen often at this point since
Tox is being actively developed and is in early pre alpha stages.

I do however sync my shared lib Tox repo with the official Tox project
regularly (usually every 1-3 days).

## Dependencies

* glib: should be available in the repositories of your distribution)
* ncurses: should be in your repo
* [libpurple: ](https://developer.pidgin.im/) should be in your repo as well
* [libsodium: ](http://download.libsodium.org/libsodium/releases/)
* [Tox: ](https://github.com/jin-eld/ProjectTox-Core) shared lib branch

Additionally you will need _gcc, autoconf, automake, libtool_ and maybe
a few other things for actually compiling the code.


I assume that you can install the development packages for libpurple and
glib using your favorite package manager, same goes for development tools,
so I'll only walk you through the steps for libsodium and Tox.

Usually I prefer not to install software system wide which does not come as
a distribution package (i.e. if there is no .rpm, .deb, etc.).

In the example below, replace _"youruser"_ with your actual user name. If you
do not provide the prefix, the installation will go to /usr/local/ which will
require root priveleges for the _make install_ step.

# libsodium

If you cloned libsodium from git you will have to run ./autogen.sh to generate
the configure script, if you downloaded a release tarball then configure will
already be there.

```bash
./configure --prefix=/home/youruser/Tox/sysroot
make
make install
```

This will install libsodium headers in /home/youruser/Tox/sysroot/include
and the library in /home/youruser/Tox/sysroot/lib.

Remember the /home/youruser/Tox/sysroot/ path, we will need it later on.

# Tox core

Clone the repo if you did not do so already:

```bash
git clone https://github.com/jin-eld/ProjectTox-Core.git
cd ProjectTox-Core
```
Generate the configure script:

```bash
autoreconf -i
```

Tell configure where to find dependencies and where to install the library,
compile and install:

```bash
./configure --with-dependency-search=/home/youruser/Tox/sysroot/ --prefix=/home/youruser/Tox/sysroot/
make
make install
```

# tox-prpl

Clone the repo if you did not do so already:

```bash
git clone https://github.com/jin-eld/tox-prpl.git
cd tox-prpl
```

Generate the configure script:

```bash
autoreconf -i
```

Tell configure where to find dependencies and where to install the plugin,
compile and install:

```bash
./configure --with-dependency-search=/home/youruser/Tox/sysroot/ --prefix=/home/youruser/Tox/sysroot/
make
make install
```
Unless you also compiled pidgin and installed it in your above "sysroot", the
plugin will not be found, so as a last step you need to:

```bash
mkdir ~/.purple/plugins/
cp /home/youruser/Tox/sysroot/lib/purple-2/libtox.so ~/.purple/plugins/
```

If you used a non standard installation location for the library, as above,
then you have to add it to your environment before running pidgin.

In the terminal where you start pidgin (assuming bash):
```bash
export LD_LIBRARY_PATH=/home/youruser/Tox/sysroot/lib
```

Now you are ready to start pidgin and to test the plugin.
