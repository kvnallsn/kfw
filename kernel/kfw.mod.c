#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf3600c71, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xf9aee87a, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0x283b8bd5, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0x34ab1e13, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0xdb9fa707, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x615d07b4, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x1b6314fd, __VMLINUX_SYMBOL_STR(in_aton) },
	{ 0x2276db98, __VMLINUX_SYMBOL_STR(kstrtoint) },
	{ 0x349cba85, __VMLINUX_SYMBOL_STR(strchr) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xf0186ad6, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0xfd826b7, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
	{ 0xa7d0ddb6, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

