#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # Kernel build steps

    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all -j 6
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs
fi

echo "Adding the Image in outdir"

cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm -rf ${OUTDIR}/rootfs
fi

# Create necessary base directories

mkdir ${OUTDIR}/rootfs

cd ${OUTDIR}/rootfs 
mkdir bin dev etc home lib lib64 proc sbin sys tmp usr var conf
mkdir usr/bin usr/lib64 usr/sbin var/log

tree -d

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # Configure busybox

    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} distclean
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
else
    cd busybox
fi

# Make and install busybox

make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} busybox -j 6
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} CONFIG_PREFIX=${OUTDIR}/rootfs install

cd ${OUTDIR}/rootfs

echo "Library dependencies"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# Add library dependencies to rootfs

cd $(${CROSS_COMPILE}gcc -print-sysroot)

cp -a lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib
cp -a lib64/ld-2.31.so ${OUTDIR}/rootfs/lib64
cp -a lib64/libm.so.6 lib64/libm-* ${OUTDIR}/rootfs/lib64
cp -a lib64/libresolv.so.2 lib64/libresolv-* ${OUTDIR}/rootfs/lib64
cp -a lib64/libc.so.6 lib64/libc-* ${OUTDIR}/rootfs/lib64

# Make device nodes

cd ${OUTDIR}/rootfs/dev

sudo mknod -m 666 null c 1 3
sudo mknod -m 666 console c 5 1

# Clean and build the writer utility

cd ${FINDER_APP_DIR}

make clean
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all

# Copy the finder related scripts and executables to the /home directory
# on the target rootfs

cp writer finder.sh finder-test.sh autorun-qemu.sh ${OUTDIR}/rootfs/home

mkdir -p ${OUTDIR}/rootfs/home/conf
cp -a conf/* ${OUTDIR}/rootfs/home/conf

cp -a conf/* ${OUTDIR}/rootfs/conf

cd ${OUTDIR}/rootfs

# Chown the root directory

sudo chown -R root.root ./

# Create initramfs.cpio.gz

find . | cpio -o -H newc | gzip > ${OUTDIR}/initramfs.cpio.gz

# Done
