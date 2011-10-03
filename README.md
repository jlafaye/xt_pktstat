xt_pktstat; an iptable module for high frequency packet accounting:

A loadable kernel module that keeps track of number of frames and bytes received per submillisecond time windows.
An iptables shared library to add/configure/remove rules
A /proc subdirectory to easily use statistics in user programs

The project consists of two directories:
- kernel: loadable kernel module, accounting code
- iptables: userland shared library to manage accounting rules

Compilation of kernel module
----------------------------

> cd kernel
> make modules
> make modules_install

Kernel headers are required for the compilation to succeed. The Makefile should automatically detect the location of those headers. If this is not the case, you can select by overriding the KERNEL_DIR variable using by the compilation script

> make KERNEL_DIR=/lib/modules/3.0.0-1-686-pae/build modules

(Re)create module dependencies 

> depmod -a

Compilation of userland shared library
--------------------------------------

> cd iptables

TODO

Creating a filter and examining data
------------------------------------

Load kernel module

> modprobe xt_pktstat

Successful loading of the module can be checked in kernel log file, usually /var/log/messages:

> grep xt_pktstat /var/log/messages
> [29246.414327] xt_pktstat: init! size:24

Create a basic rule, e.g. 

TODO

