// SPDX-License-Identifier: GPL-2.0
/* VM-only producer; excluded from the installable kernel patch. */
#include <linux/dma-fence.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/sync_file.h>

struct test_fence {
	struct dma_fence fence;
	spinlock_t lock;
};

static const char *test_name(struct dma_fence *fence)
{
	return "cake_signal_test";
}

static void test_release(struct dma_fence *fence)
{
	kfree(container_of(fence, struct test_fence, fence));
}

static const struct dma_fence_ops test_ops = {
	.get_driver_name = test_name,
	.get_timeline_name = test_name,
	.release = test_release,
};

static int test_open(struct inode *inode, struct file *file)
{
	struct test_fence *f = kzalloc(sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	spin_lock_init(&f->lock);
	dma_fence_init(&f->fence, &test_ops, &f->lock, dma_fence_context_alloc(1), 1);
	file->private_data = f;
	return 0;
}

static int test_close(struct inode *inode, struct file *file)
{
	struct test_fence *f = file->private_data;

	dma_fence_put(&f->fence);
	return 0;
}

static long test_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct test_fence *f = file->private_data;
	struct sync_file *sync;
	int fd;

	switch (cmd) {
	case _IO('C', 1):
		return dma_fence_wait(&f->fence, true);
	case _IO('C', 2):
		dma_fence_signal(&f->fence);
		return 0;
	case _IO('C', 3):
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0)
			return fd;
		sync = sync_file_create(&f->fence);
		if (!sync) {
			put_unused_fd(fd);
			return -ENOMEM;
		}
		fd_install(fd, sync->file);
		return fd;
	default:
		return -EINVAL;
	}
}

static const struct file_operations test_fops = {
	.owner = THIS_MODULE,
	.open = test_open,
	.release = test_close,
	.unlocked_ioctl = test_ioctl,
};

static struct miscdevice test_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "cake-signal-test",
	.fops = &test_fops,
	.mode = 0600,
};

static int __init test_init(void)
{
	return misc_register(&test_device);
}
device_initcall(test_init);
