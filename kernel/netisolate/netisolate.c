// SPDX-License-Identifier: GPL-2.0
/*
 * netisolate - UID 级联网阻止 (内核态)
 *
 * 原理: netfilter LOCAL_OUT hook, 检查 socket 属主 UID 是否在阻止列表
 *       → 是则 REJECT (回 ICMP port unreachable → 应用立即 ECONNREFUSED,
 *         与 FolkPatch 一致: 应用直接认为没网, 而非丢包假有网)
 *
 * supercall 命令 (通过 KSU supercall ioctl):
 *   CMD_NETISOLATE_ENABLE      启用/禁用 (0/1)
 *   CMD_NETISOLATE_UID_ADD     添加 UID
 *   CMD_NETISOLATE_UID_REMOVE  移除 UID
 *   CMD_NETISOLATE_UID_CLEAR   清空
 *   CMD_NETISOLATE_UID_LIST    查询列表
 *
 * 2026-08-16: ReSukiSU Ultra 联网阻止功能
 */
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/netisolate_def.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/icmp.h>
#include <net/netfilter/ipv4/nf_reject.h>
#ifdef CONFIG_IPV6
#include <net/netfilter/ipv6/nf_reject.h>
#include <linux/icmpv6.h>
#endif

#define NETISOLATE_MAX_UID 256

static unsigned int netisolate_uids[NETISOLATE_MAX_UID];
static unsigned int netisolate_uid_count;
static bool netisolate_enabled;
static DEFINE_SPINLOCK(netisolate_lock);

static bool netisolate_uid_blocked(kuid_t uid)
{
    unsigned int i;
    unsigned int target = from_kuid(&init_user_ns, uid);

    if (!netisolate_enabled || netisolate_uid_count == 0)
        return false;

    spin_lock(&netisolate_lock);
    for (i = 0; i < netisolate_uid_count; i++) {
        if (netisolate_uids[i] == target) {
            spin_unlock(&netisolate_lock);
            return true;
        }
    }
    spin_unlock(&netisolate_lock);
    return false;
}

static unsigned int netisolate_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct sock *sk;

    if (!netisolate_enabled || !skb)
        return NF_ACCEPT;

    sk = skb->sk;
    if (!sk || !sk->sk_uid.val)
        return NF_ACCEPT;

    if (netisolate_uid_blocked(sk->sk_uid)) {
        pr_info("netisolate: rejected uid=%u\n", from_kuid(&init_user_ns, sk->sk_uid));
        /* REJECT 语义: 回 ICMP port unreachable, 让应用立即 ECONNREFUSED
		 * (LOCAL_OUT 下 dev=NULL, nf_reject_* 内部自行路由) */
        if (skb->protocol == htons(ETH_P_IP)) {
            nf_reject_skb_v4_unreach(state->net, skb, NULL, state->hook, ICMP_PORT_UNREACH);
#ifdef CONFIG_IPV6
        } else if (skb->protocol == htons(ETH_P_IPV6)) {
            nf_reject_skb_v6_unreach(state->net, skb, NULL, state->hook, ICMPV6_PORT_UNREACH);
#endif
        }
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops netisolate_ops[] = {
    {
        .hook = netisolate_hook,
        .pf = NFPROTO_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
};

/* ===== supercall 接口 ===== */

void netisolate_set_enabled(bool enable)
{
    spin_lock(&netisolate_lock);
    netisolate_enabled = enable;
    spin_unlock(&netisolate_lock);
    pr_info("netisolate: %s\n", enable ? "enabled" : "disabled");
}

int netisolate_uid_add(unsigned int uid)
{
    unsigned int i;

    spin_lock(&netisolate_lock);
    if (netisolate_uid_count >= NETISOLATE_MAX_UID) {
        spin_unlock(&netisolate_lock);
        return -ENOSPC;
    }
    for (i = 0; i < netisolate_uid_count; i++) {
        if (netisolate_uids[i] == uid) {
            spin_unlock(&netisolate_lock);
            return 0;
        }
    }
    netisolate_uids[netisolate_uid_count++] = uid;
    spin_unlock(&netisolate_lock);
    pr_info("netisolate: add uid=%u (count=%u)\n", uid, netisolate_uid_count);
    return 0;
}

int netisolate_uid_remove(unsigned int uid)
{
    unsigned int i, j;
    bool found = false;

    spin_lock(&netisolate_lock);
    for (i = 0; i < netisolate_uid_count; i++) {
        if (netisolate_uids[i] == uid) {
            for (j = i; j < netisolate_uid_count - 1; j++)
                netisolate_uids[j] = netisolate_uids[j + 1];
            netisolate_uid_count--;
            found = true;
            break;
        }
    }
    spin_unlock(&netisolate_lock);
    if (found)
        pr_info("netisolate: remove uid=%u (count=%u)\n", uid, netisolate_uid_count);
    return found ? 0 : -ENOENT;
}

void netisolate_uid_clear(void)
{
    spin_lock(&netisolate_lock);
    netisolate_uid_count = 0;
    spin_unlock(&netisolate_lock);
    pr_info("netisolate: clear all\n");
}

unsigned int netisolate_get_uid_count(void)
{
    return netisolate_uid_count;
}

void netisolate_get_uids(unsigned int *buf, unsigned int max)
{
    unsigned int i;
    unsigned int n = netisolate_uid_count < max ? netisolate_uid_count : max;

    spin_lock(&netisolate_lock);
    for (i = 0; i < n; i++)
        buf[i] = netisolate_uids[i];
    spin_unlock(&netisolate_lock);
}

bool netisolate_is_enabled(void)
{
    return netisolate_enabled;
}

/* LSM socket_connect 配合: 当前进程 UID 是否在阻止列表 (彻底断网: connect 直接失败) */
bool netisolate_should_block_current(void)
{
    if (!netisolate_enabled || netisolate_uid_count == 0)
        return false;
    return netisolate_uid_blocked(current_uid());
}
EXPORT_SYMBOL_GPL(netisolate_should_block_current);

/* ===== supercall 分发 (ksud netisolate 命令, 走 SUSFS_MAGIC 通道) ===== */
int netisolate_handle_cmd(unsigned int cmd, void __user **arg)
{
    unsigned int val;

    switch (cmd) {
    case CMD_NETISOLATE_ENABLE:
        if (get_user(val, (unsigned int __user *)*arg))
            return -EFAULT;
        netisolate_set_enabled(val ? true : false);
        break;
    case CMD_NETISOLATE_UID_ADD:
        if (get_user(val, (unsigned int __user *)*arg))
            return -EFAULT;
        return netisolate_uid_add(val);
    case CMD_NETISOLATE_UID_REMOVE:
        if (get_user(val, (unsigned int __user *)*arg))
            return -EFAULT;
        return netisolate_uid_remove(val);
    case CMD_NETISOLATE_UID_CLEAR:
        netisolate_uid_clear();
        break;
    case CMD_NETISOLATE_UID_LIST: {
        unsigned int out[NETISOLATE_MAX_UID + 1];

        out[0] = netisolate_get_uid_count();
        netisolate_get_uids(&out[1], NETISOLATE_MAX_UID);
        if (copy_to_user(*arg, out, sizeof(out)))
            return -EFAULT;
        break;
    }
    case CMD_NETISOLATE_GET_STATE: {
        struct {
            unsigned int enabled;
            unsigned int count;
        } state;

        state.enabled = netisolate_is_enabled() ? 1 : 0;
        state.count = netisolate_get_uid_count();
        if (copy_to_user(*arg, &state, sizeof(state)))
            return -EFAULT;
        break;
    }
    default:
        return -EINVAL;
    }
    return 0;
}

/* ===== 配置文件读取 (开机自动加载) ===== */
#define NETISOLATE_DIR "/data/adb/ksu/netisolate"
#define NETISOLATE_ENABLE_FILE NETISOLATE_DIR "/enabled"
#define NETISOLATE_UIDS_FILE NETISOLATE_DIR "/uids"

static bool file_read_bool(const char *path)
{
    struct file *f;
    char buf[8] = { 0 };
    bool result = false;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return false;
    if (kernel_read(f, buf, sizeof(buf) - 1, &f->f_pos) > 0) {
        result = (buf[0] == '1');
    }
    filp_close(f, NULL);
    return result;
}

static void file_read_uids(const char *path)
{
    struct file *f;
    char *buf;
    ssize_t n;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return;
    /* 动态分配: 避免 4KB 栈数组触发 frame-larger-than (DDK Werror) */
    buf = kzalloc(4096, GFP_KERNEL);
    if (!buf) {
        filp_close(f, NULL);
        return;
    }
    n = kernel_read(f, buf, 4095, &f->f_pos);
    filp_close(f, NULL);
    if (n <= 0) {
        kfree(buf);
        return;
    }
    buf[n] = '\0';

    /* 解析每行一个 UID */
    netisolate_uid_clear();
    {
        char *p = buf;
        while (*p) {
            char *end = p;
            while (*end && *end != '\n')
                end++;
            if (*end)
                *end = '\0';
            {
                unsigned long uid = 0;
                int i;
                for (i = 0; p[i] >= '0' && p[i] <= '9'; i++)
                    uid = uid * 10 + (p[i] - '0');
                if (uid > 0)
                    netisolate_uid_add(uid);
            }
            p = end + 1;
        }
    }
    kfree(buf);
}

static int __init netisolate_init(void)
{
    int ret;

    ret = nf_register_net_hooks(&init_net, netisolate_ops, ARRAY_SIZE(netisolate_ops));
    if (ret) {
        pr_err("netisolate: nf_register_net_hooks failed (%d)\n", ret);
        return ret;
    }
    /* 开机加载配置 (管理器写入 /data/adb/ksu/netisolate/) */
    netisolate_set_enabled(file_read_bool(NETISOLATE_ENABLE_FILE));
    file_read_uids(NETISOLATE_UIDS_FILE);
    pr_info("netisolate: initialized (enabled=%d, uids=%u)\n", netisolate_is_enabled(), netisolate_get_uid_count());
    return 0;
}

static void __exit netisolate_exit(void)
{
    nf_unregister_net_hooks(&init_net, netisolate_ops, ARRAY_SIZE(netisolate_ops));
    pr_info("netisolate: exited\n");
}

late_initcall(netisolate_init);
module_exit(netisolate_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UID-level network isolation (ReSukiSU Ultra)");

#ifdef CONFIG_KSU_FEATURE
#include "policy/feature.h"

static int netisolate_feature_get(u64 *value)
{
    *value = netisolate_is_enabled() ? 1 : 0;
    return 0;
}

static int netisolate_feature_set(u64 value)
{
    netisolate_set_enabled(value != 0);
    return 0;
}

static const struct ksu_feature_handler netisolate_handler = {
    .feature_id = KSU_FEATURE_NETISOLATE,
    .name = "netisolate",
    .get_handler = netisolate_feature_get,
    .set_handler = netisolate_feature_set,
};

static int __init netisolate_register_feature(void)
{
    if (ksu_register_feature_handler(&netisolate_handler))
        pr_err("netisolate: failed to register feature\n");
    return 0;
}
late_initcall(netisolate_register_feature);
#endif
