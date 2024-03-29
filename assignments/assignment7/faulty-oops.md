# Assignment 7 - Faulty oops analysis
The analysis shows how to locate the faulty line in the faulty kernel driver based on kernel oops message and stack trace.

## System setting
- The driver source code (https://github.com/cu-ecen-aeld/assignment-7-tkuchynsky)[https://github.com/cu-ecen-aeld/assignment-7-tkuchynsky] was cloned from [lld3](https://github.com/cu-ecen-aeld/ldd3) kernel driver examples that based on original driver  from [Linux Device Drivers 3 book](http://lwn.net/Kernel/LDD3/).
- The buildroot configuration repository for the assignment (https://github.com/cu-ecen-aeld/assignment-6-tkuchynsky)[https://github.com/cu-ecen-aeld/assignment-6-tkuchynsky]. 
 
### Running qemu image
```
$ ./runqemu.sh 
Booting Linux on physical CPU 0x0000000000 [0x410fd034]
Linux version 5.15.18 (taras@taras-Latitude-5520) (aarch64-buildroot-linux-gnu-gcc.br_real (Buildroot 2023.02-282-gd89fdaea2b) 11.3.0, GNU ld (GNU Binutils) 2.38) #1 SMP Thu Sep 28 17:54:13 CEST 2023
Machine model: linux,dummy-virt
efi: UEFI not found.
Zone ranges:
  DMA      [mem 0x0000000040000000-0x0000000047ffffff]
  DMA32    empty
  Normal   empty
Movable zone start for each node
Early memory node ranges
  node   0: [mem 0x0000000040000000-0x0000000047ffffff]
Initmem setup node 0 [mem 0x0000000040000000-0x0000000047ffffff]
psci: probing for conduit method from DT.
psci: PSCIv0.2 detected in firmware.
psci: Using standard PSCI v0.2 function IDs
psci: Trusted OS migration not required
percpu: Embedded 17 pages/cpu s32344 r8192 d29096 u69632
Detected VIPT I-cache on CPU0
CPU features: detected: ARM erratum 843419
CPU features: detected: ARM erratum 845719
Built 1 zonelists, mobility grouping on.  Total pages: 32256
Kernel command line: rootwait root=/dev/vda console=ttyAMA0
Dentry cache hash table entries: 16384 (order: 5, 131072 bytes, linear)
Inode-cache hash table entries: 8192 (order: 4, 65536 bytes, linear)
mem auto-init: stack:off, heap alloc:off, heap free:off
Memory: 116484K/131072K available (7040K kernel code, 838K rwdata, 1508K rodata, 1088K init, 320K bss, 14588K reserved, 0K cma-reserved)
SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
rcu: Hierarchical RCU implementation.
rcu: 	RCU restricting CPUs from NR_CPUS=256 to nr_cpu_ids=1.
rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.
rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1
NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0
Root IRQ handler: gic_handle_irq
GICv2m: range[mem 0x08020000-0x08020fff], SPI[80:143]
random: get_random_bytes called from start_kernel+0x3f0/0x5fc with crng_init=0
arch_timer: cp15 timer(s) running at 62.50MHz (virt).
clocksource: arch_sys_counter: mask: 0xffffffffffffff max_cycles: 0x1cd42e208c, max_idle_ns: 881590405314 ns
sched_clock: 56 bits at 62MHz, resolution 16ns, wraps every 4398046511096ns
Console: colour dummy device 80x25
Calibrating delay loop (skipped), value calculated using timer frequency.. 125.00 BogoMIPS (lpj=250000)
pid_max: default: 32768 minimum: 301
Mount-cache hash table entries: 512 (order: 0, 4096 bytes, linear)
Mountpoint-cache hash table entries: 512 (order: 0, 4096 bytes, linear)
/cpus/cpu-map: empty cluster
rcu: Hierarchical SRCU implementation.
EFI services will not be available.
smp: Bringing up secondary CPUs ...
smp: Brought up 1 node, 1 CPU
SMP: Total of 1 processors activated.
CPU features: detected: 32-bit EL0 Support
CPU features: detected: CRC32 instructions
CPU: All CPU(s) started at EL1
alternatives: patching kernel code
devtmpfs: initialized
clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
futex hash table entries: 256 (order: 2, 16384 bytes, linear)
DMI not present or invalid.
NET: Registered PF_NETLINK/PF_ROUTE protocol family
DMA: preallocated 128 KiB GFP_KERNEL pool for atomic allocations
DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.
ASID allocator initialised with 65536 entries
Serial: AMBA PL011 UART driver
9000000.pl011: ttyAMA0 at MMIO 0x9000000 (irq = 47, base_baud = 0) is a PL011 rev1
printk: console [ttyAMA0] enabled
iommu: Default domain type: Translated 
iommu: DMA domain TLB invalidation policy: strict mode 
vgaarb: loaded
SCSI subsystem initialized
pps_core: LinuxPPS API ver. 1 registered
pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
PTP clock support registered
clocksource: Switched to clocksource arch_sys_counter
NET: Registered PF_INET protocol family
IP idents hash table entries: 2048 (order: 2, 16384 bytes, linear)
tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)
TCP established hash table entries: 1024 (order: 1, 8192 bytes, linear)
TCP bind hash table entries: 1024 (order: 2, 16384 bytes, linear)
TCP: Hash tables configured (established 1024 bind 1024)
UDP hash table entries: 256 (order: 1, 8192 bytes, linear)
UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)
NET: Registered PF_UNIX/PF_LOCAL protocol family
PCI: CLS 0 bytes, default 64
hw perfevents: enabled with armv8_pmuv3 PMU driver, 5 counters available
workingset: timestamp_bits=46 max_order=15 bucket_order=0
fuse: init (API version 7.34)
Block layer SCSI generic (bsg) driver version 0.4 loaded (major 249)
io scheduler mq-deadline registered
io scheduler kyber registered
pci-host-generic 4010000000.pcie: host bridge /pcie@10000000 ranges:
pci-host-generic 4010000000.pcie:       IO 0x003eff0000..0x003effffff -> 0x0000000000
pci-host-generic 4010000000.pcie:      MEM 0x0010000000..0x003efeffff -> 0x0010000000
pci-host-generic 4010000000.pcie:      MEM 0x8000000000..0xffffffffff -> 0x8000000000
pci-host-generic 4010000000.pcie: Memory resource size exceeds max for 32 bits
pci-host-generic 4010000000.pcie: ECAM at [mem 0x4010000000-0x401fffffff] for [bus 00-ff]
pci-host-generic 4010000000.pcie: PCI host bridge to bus 0000:00
pci_bus 0000:00: root bus resource [bus 00-ff]
pci_bus 0000:00: root bus resource [io  0x0000-0xffff]
pci_bus 0000:00: root bus resource [mem 0x10000000-0x3efeffff]
pci_bus 0000:00: root bus resource [mem 0x8000000000-0xffffffffff]
pci 0000:00:00.0: [1b36:0008] type 00 class 0x060000
pci 0000:00:01.0: [1af4:1005] type 00 class 0x00ff00
pci 0000:00:01.0: reg 0x10: [io  0x0000-0x001f]
pci 0000:00:01.0: reg 0x20: [mem 0x00000000-0x00003fff 64bit pref]
pci 0000:00:01.0: BAR 4: assigned [mem 0x8000000000-0x8000003fff 64bit pref]
pci 0000:00:01.0: BAR 0: assigned [io  0x1000-0x101f]
virtio-pci 0000:00:01.0: enabling device (0000 -> 0003)
cacheinfo: Unable to detect cache hierarchy for CPU 0
virtio_blk virtio0: [vda] 122880 512-byte logical blocks (62.9 MB/60.0 MiB)
random: fast init done
random: crng init done
rtc-pl031 9010000.pl031: registered as rtc0
rtc-pl031 9010000.pl031: setting system clock to 2023-10-08T10:10:35 UTC (1696759835)
NET: Registered PF_INET6 protocol family
Segment Routing with IPv6
In-situ OAM (IOAM) with IPv6
sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
NET: Registered PF_PACKET protocol family
NET: Registered PF_KEY protocol family
NET: Registered PF_VSOCK protocol family
registered taskstats version 1
EXT4-fs (vda): INFO: recovery required on readonly filesystem
EXT4-fs (vda): write access will be enabled during recovery
EXT4-fs (vda): recovery complete
EXT4-fs (vda): mounted filesystem with ordered data mode. Opts: (null). Quota mode: disabled.
VFS: Mounted root (ext4 filesystem) readonly on device 254:0.
devtmpfs: mounted
Freeing unused kernel memory: 1088K
Run /sbin/init as init process
EXT4-fs (vda): re-mounted. Opts: (null). Quota mode: disabled.
Starting syslogd: OK
Starting klogd: OK
Running sysctl: OK
Seeding 2048 bits and crediting
Saving 2048 bits of creditable seed for next boot
Starting network: udhcpc: started, v1.36.0
udhcpc: broadcasting discover
udhcpc: broadcasting select for 10.0.2.15, server 10.0.2.2
udhcpc: lease of 10.0.2.15 obtained from 10.0.2.2, lease time 86400
deleting routers
adding dns 10.0.2.3
OK
Starting dropbear sshd: OK
Loading ...
scull: loading out-of-tree module taints kernel.
scullsingle registered at f800008
sculluid registered at f800009
scullwuid registered at f80000a
scullpriv registered at f80000b
Load our module, exit on failure
Get the major number (allocated with allocate_chrdev_region) from /proc/devices
Remove any existing /dev node for /dev/faulty
Add a node for our device at /dev/faulty using mknod
Change group owner to staff
Change access mode to 664
Hello, world ==> tkuchynsky <==
... done
Starting daemon: aesdsocketRun as a daemon ...
...

Welcome to Buildroot
buildroot login: root
Password: 
#
```
## Running test
### The following shell command can be used to reproduce the issue and get kernel oops error message
```  
# echo “hello_world” > /dev/faulty 
```
### The kernel oops error message
```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x96000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=000000004262c000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 96000045 [#1] SMP
Modules linked in: hello(O) faulty(O) scull(O)
CPU: 0 PID: 151 Comm: sh Tainted: G           O      5.15.18 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x14/0x20 [faulty]
lr : vfs_write+0xa8/0x2a0
sp : ffffffc008c83d80
x29: ffffffc008c83d80 x28: ffffff80026a2640 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000040000000 x22: 0000000000000012 x21: 000000556b84b980
x20: 000000556b84b980 x19: ffffff80026c3100 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc0006f7000 x3 : ffffffc008c83df0
x2 : 0000000000000012 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0x100
 do_el0_svc+0x44/0xb0
 el0_svc+0x28/0x80
 el0t_64_sync_handler+0xa4/0x130
 el0t_64_sync+0x1a0/0x1a4
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace e6773e6b308a95f9 ]---

Welcome to Buildroot
buildroot login: 
```

## Analysis of kernel oops message
### There is an error messahe in cernel logs
```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
``` 
That means that some kernel component try to read at virtual address 0000000000000000 that cause system crash.

```
pc : faulty_write+0x14/0x20 [faulty]
```
This happend in faulty_write function with 0x14 bytes extention

```
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
```
  Call trace shows that faulty_writ fanction was caled from ksys_write function

### Location of the memory violation access in code
The faulty_write function include an memmory bug at the begining on function body:
```
ssize_t faulty_write (struct file *filp, const char __user *buf, size_t count,
		loff_t *pos)
{
	/* make a simple fault by dereferencing a NULL pointer */
	*(int *)0 = 0; // <= dereference at virtual address 0000000000000000
	return 0;
}
```  
