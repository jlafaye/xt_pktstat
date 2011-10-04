xt_pktstat; an iptable module for high frequency packet accounting
------------------------------------------------------------------

A loadable kernel module that keeps track of number of frames and bytes received per submillisecond time windows.
An iptables shared library to add/configure/remove rules
A /proc subdirectory to easily use statistics in user programs

The project several components:
  * kernel: loadable kernel module, accounting code
  * iptables: userland shared library to manage accounting rules

Internally, xt_pkstat uses a FIFO filled in a netfilter hook and emptied when reading pseudo-file in /proc. It is up to the user program to ensure that the pseudo-file is regulary read to prevent statistics from accumulating in the FIFO. In case of a full FIFO, network stack will not be able to push new statistics samples onto the FIFO. Consistency of the statistics will be kepts but accuracy will be lost.

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
> make all

Iptables development package must be installed for the library to compile. In case headers are not installed in a standard location, CFLAFS can be changed in the Makefile

Creating a filter and examining data
------------------------------------

Load kernel module

> modprobe xt_pktstat

Successful loading of the module can be checked in kernel log file, usually /var/log/messages:

> grep xt_pktstat /var/log/messages
> [29246.414327] xt_pktstat: init! size:24

Display help and usage for the pktstat module, iptables command must be prefixed with the location of the libxt_pktstat.so shared library.

> XTABLES_LIBDIR=$PWD:/lib/xtables iptables -m pktstat --help

Create a basic rule, with e.g. the following parameters
  * `period`: width of a time bucket, here 100ms
  * `samples`: max number of samples allowed in the fifo, here 20

> XTABLES_LIBDIR=$PWD:/lib/xtables iptables -m pktstat --period 100 --samples 20 -A INPUT

Read the data

> cat /proc/net/xt_pktstat/0/data
 
```
# timestamp frames bytes
1313702809400000000 1235 485932
1313702809500000000 1235 485932
1313702809600000000 1235 485932
1313702809700000000 1235 485932
```

