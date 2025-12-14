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
	{ 0x3d568d84, "class_create" },
	{ 0x0cf2b0e8, "device_create" },
	{ 0xc68d7731, "device_destroy" },
	{ 0xfbc10eaa, "class_destroy" },
	{ 0x52b15b3b, "__unregister_chrdev" },
	{ 0xc7ffe1aa, "si_meminfo" },
	{ 0x96c07e76, "const_pcpu_hot" },
	{ 0xb1ad3f2f, "boot_cpu_data" },
	{ 0x9479a1e8, "strnlen" },
	{ 0xf296206e, "nr_cpu_ids" },
	{ 0x2182515b, "__num_online_cpus" },
	{ 0xb5c51982, "__cpu_possible_mask" },
	{ 0x3a645690, "__bitmap_weight" },
	{ 0x16da3d64, "si_mem_available" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0xa2152099, "init_task" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0x12ca6142, "ktime_get_with_offset" },
	{ 0xb311a158, "ns_to_timespec64" },
	{ 0x8a23df34, "set_normalized_timespec64" },
	{ 0xdd6830c7, "sprintf" },
	{ 0xa53f4e29, "memcpy" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0xe8213e80, "_printk" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x96522db6, "__register_chrdev" },
	{ 0x70eca2ca, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x3d568d84,
	0x0cf2b0e8,
	0xc68d7731,
	0xfbc10eaa,
	0x52b15b3b,
	0xc7ffe1aa,
	0x96c07e76,
	0xb1ad3f2f,
	0x9479a1e8,
	0xf296206e,
	0x2182515b,
	0xb5c51982,
	0x3a645690,
	0x16da3d64,
	0xd272d446,
	0xa2152099,
	0xd272d446,
	0x12ca6142,
	0xb311a158,
	0x8a23df34,
	0xdd6830c7,
	0xa53f4e29,
	0xe54e0a6b,
	0xa61fd7aa,
	0x092a35a2,
	0xd272d446,
	0xd272d446,
	0xd272d446,
	0x092a35a2,
	0xe8213e80,
	0x90a48d82,
	0x96522db6,
	0x70eca2ca,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"class_create\0"
	"device_create\0"
	"device_destroy\0"
	"class_destroy\0"
	"__unregister_chrdev\0"
	"si_meminfo\0"
	"const_pcpu_hot\0"
	"boot_cpu_data\0"
	"strnlen\0"
	"nr_cpu_ids\0"
	"__num_online_cpus\0"
	"__cpu_possible_mask\0"
	"__bitmap_weight\0"
	"si_mem_available\0"
	"__rcu_read_lock\0"
	"init_task\0"
	"__rcu_read_unlock\0"
	"ktime_get_with_offset\0"
	"ns_to_timespec64\0"
	"set_normalized_timespec64\0"
	"sprintf\0"
	"memcpy\0"
	"__fortify_panic\0"
	"__check_object_size\0"
	"_copy_to_user\0"
	"__stack_chk_fail\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"_copy_from_user\0"
	"_printk\0"
	"__ubsan_handle_out_of_bounds\0"
	"__register_chrdev\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "EC5A864349422A8FFF8D254");
