#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x96522db6, "__register_chrdev" },
	{ 0x3d568d84, "class_create" },
	{ 0x0cf2b0e8, "device_create" },
	{ 0xc68d7731, "device_destroy" },
	{ 0xfbc10eaa, "class_destroy" },
	{ 0x52b15b3b, "__unregister_chrdev" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0xe8213e80, "_printk" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0x70eca2ca, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x96522db6,
	0x3d568d84,
	0x0cf2b0e8,
	0xc68d7731,
	0xfbc10eaa,
	0x52b15b3b,
	0xd272d446,
	0xd272d446,
	0x092a35a2,
	0xe8213e80,
	0x90a48d82,
	0x092a35a2,
	0x70eca2ca,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__register_chrdev\0"
	"class_create\0"
	"device_create\0"
	"device_destroy\0"
	"class_destroy\0"
	"__unregister_chrdev\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"_copy_from_user\0"
	"_printk\0"
	"__ubsan_handle_out_of_bounds\0"
	"_copy_to_user\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "37F20FA7FCC4BC166C57F7D");
