#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x14607ce2, "usb_put_dev" },
	{ 0x37a0cba, "kfree" },
	{ 0x9ad1f3c7, "usb_free_urb" },
	{ 0x904f8725, "usb_deregister" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0xcb742157, "kmalloc_caches" },
	{ 0xfe1d3f1a, "kmalloc_trace" },
	{ 0x92e2e2fc, "crypto_alloc_akcipher" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x43babd19, "sg_init_one" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0xe553b626, "crypto_destroy_tfm" },
	{ 0x196e7f07, "usb_bulk_msg" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0x84df77fa, "usb_get_dev" },
	{ 0x86b5950e, "usb_alloc_urb" },
	{ 0xbc1070b0, "usb_submit_urb" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x122c3a7e, "_printk" },
	{ 0x3d4ed8ba, "usb_register_driver" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x8d5e53af, "module_layout" },
};

MODULE_INFO(depends, "");

MODULE_ALIAS("usb:v*p*d*dc*dsc*dp*ic08isc06ip50in*");

MODULE_INFO(srcversion, "7EAF5B84BE9A27A2B13184D");
