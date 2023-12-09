/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>   // file_operations
#include <linux/slab.h> // kmalloc()
#include "aesdchar.h"
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Your Name Here"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * Handle open
     */

    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    ssize_t retval = 0;

    struct aesd_dev *dev = NULL;

    struct aesd_buffer_entry *entry = NULL;
    size_t offset = 0;
    void *kernel_data = NULL;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    /**
     * Handle read
     */

    if (filp == NULL || buf == NULL)
    {
        return -EINVAL;
    }

    dev = filp->private_data;

    if (mutex_lock_interruptible(&dev->device_mutex) != 0)
    {
        PDEBUG("Cannot lock mutex!");
        return -ERESTARTSYS;
    }

    if (dev == NULL)
    {
        mutex_unlock(&dev->device_mutex);
        return -EPERM;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &offset);

    if (entry == NULL)
    {
        mutex_unlock(&dev->device_mutex);
        return 0;
    }

    size_t count_to_read = entry->size - offset;

    if (count_to_read > count)
    {
        count_to_read = count;
    }

    if (copy_to_user(buf, entry->buffptr + offset, count_to_read) != 0)
    {
        PDEBUG("Cannot copy to user space\n");
        mutex_unlock(&dev->device_mutex);
        return -EFAULT;
    }

    *f_pos = *f_pos + count_to_read;

    retval = count_to_read;

    mutex_unlock(&dev->device_mutex);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;

    struct aesd_buffer_entry add_entry = {0};
    size_t count_to_write = 0;
    char *new_line_char_ptr = NULL;

    if (filp == NULL || buf == NULL)
    {
        return -EINVAL;
    }

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    /**
     * Handle write
     */

    char *kernel_buf = kmalloc(count, GFP_KERNEL);
    if (kernel_buf == NULL)
    {
        PDEBUG("Cannot kmalloc write buffer!");
        return -ENOMEM;
    }

    struct aesd_dev *dev = filp->private_data;

    if (mutex_lock_interruptible(&dev->device_mutex) != 0)
    {
        kfree(kernel_buf);
        return -ERESTARTSYS;
    }

    if (dev == NULL)
    {
        mutex_unlock(&dev->device_mutex);
        kfree(kernel_buf);
        return -EPERM;
    }

    if (copy_from_user(kernel_buf, buf, count) != 0)
    {
        mutex_unlock(&dev->device_mutex);
        kfree(kernel_buf);
        return -EPERM;
    }

    count_to_write = count;

    new_line_char_ptr = memchr(kernel_buf, '\n', count_to_write);

    if (new_line_char_ptr != NULL)
    {
        count_to_write = 1 + (new_line_char_ptr - kernel_buf);
    }

    dev->device_buffer = krealloc(dev->device_buffer, dev->device_buffer_size + count_to_write, GFP_KERNEL);
    if (dev->device_buffer == NULL)
    {
        mutex_unlock(&dev->device_mutex);
        kfree(kernel_buf);

        return -ENOMEM;
    }

    memcpy(dev->device_buffer + dev->device_buffer_size, kernel_buf, count_to_write);
    dev->device_buffer_size += count_to_write;

    if (new_line_char_ptr != NULL)
    {
        add_entry.buffptr = dev->device_buffer;
        add_entry.size = dev->device_buffer_size;

        aesd_circular_buffer_add_entry(&dev->circular_buffer, &add_entry);

        dev->device_buffer = NULL;
        dev->device_buffer_size = 0;
    }

    mutex_unlock(&dev->device_mutex);

    return count;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * Initialize the AESD specific portion of the device
     */

    mutex_init(&aesd_device.device_mutex);

    aesd_circular_buffer_init(&aesd_device.circular_buffer);

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * Cleanup AESD specific portions here
     */

    struct aesd_buffer_entry *buff_entry = NULL;
    int index = 0;

    unregister_chrdev_region(devno, 1);

    AESD_CIRCULAR_BUFFER_FOREACH(buff_entry, &aesd_device.circular_buffer, index) { kfree(buff_entry->buffptr); }

    mutex_destroy(&aesd_device.device_mutex);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
