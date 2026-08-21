#ifdef CONFIG_KSU_FEATURE_ADBROOT

static bool ksu_adb_root __read_mostly = false;

static inline long is_exec_adbd(const char __user **filename_user)
{
	// should be bigger than `/apex/com.android.adbd/bin/adbd`
	char buf[40] = { 0 };
	size_t copysize = sizeof("/apex/com.android.adbd/bin/adbd");

	if (!!copy_from_user(buf, *filename_user, copysize))
		return 0;

	if (!!endswith(buf, "/adbd"))
		return 0;

	pr_info("%s: adbd: %s \n", __func__, buf);

	return 1;
}

static long is_libadbroot_ok()
{
	static const char kLibAdbRoot[] = "/data/adb/ksu/lib/libadbroot.so";
	struct path path;
	long ret = kern_path(kLibAdbRoot, 0, &path);
	if (ret < 0) {
		if (ret == -ENOENT) {
			pr_err("libadbroot.so not exists, skip adb root. Please run `ksud install`\n");
			ret = 0;
		} else {
			pr_err("access libadbroot.so failed: %ld, skip adb root\n", ret);
		}
		return ret;
	} else {
		ret = 1;
	}
	path_put(&path);
	return ret;
}

static noinline void do_ksu_adb_root_execve_user(void *restrict filename, void *restrict envp_in)
{
	if (likely(ksu_is_seccomp_enabled()))
		return;

	uid_t uid = current_euid().val;
	if (uid != 0 && uid != 2000)
        	return;

	// filename is void * char __user *
	const char __user **filename_user = (const char __user **)filename;

	if (likely(!is_exec_adbd(filename_user)))
		return;

	if (unlikely(!is_libadbroot_ok()))
		return;

	if (setup_ld_preload((void ***)envp_in))
		return;

	pr_info("escape to root for adb\n");
	escape_to_root_for_adb_root();
	escape_with_root_profile(); // why is this needed for 3.x?
	return;
}

static noinline void do_ksu_adb_root_execve_kernel(void *restrict filename, void *restrict envp_in)
{
	if (likely(ksu_is_seccomp_enabled()))
		return;

	uid_t uid = current_euid().val;
	if (uid != 0 && uid != 2000)
        	return;

	if (!filename)
		return;

	// filename is char **
	if (!*(void **)filename)
		return;

	if (!!endswith(*(char **)filename, "/adbd"))
		return;

	if (unlikely(!is_libadbroot_ok()))
		return;

	if (!envp_in)
		return;

	struct user_arg_ptr *envp = (struct user_arg_ptr *)envp_in;

	void ***envp_addr = (void ***)&envp->ptr.native;
#ifdef CONFIG_COMPAT
	if (unlikely(envp->is_compat))
		envp_addr = (void ***)&envp->ptr.compat;
#endif

	pr_info("%s: envp 0x%lx \n", __func__, (uintptr_t)*envp_addr );

	if (setup_ld_preload(envp_addr))
		return; 

	pr_info("escape to root for adb\n");
	escape_to_root_for_adb_root();
	escape_with_root_profile(); // why is this needed?
	return;
}

#ifdef KSU_CAN_USE_JUMP_LABEL // see kernel_compat.h

DEFINE_STATIC_KEY_FALSE(ksu_adb_root_key);

static inline void ksu_adb_root_execve_user(void *restrict filename, void *restrict envp_in)
{
	if (static_branch_unlikely(&ksu_adb_root_key))
		do_ksu_adb_root_execve_user(filename, envp_in);
}
static inline void ksu_adb_root_execve_kernel(void *restrict filename, void *restrict envp_in)
{
	if (static_branch_unlikely(&ksu_adb_root_key))
		do_ksu_adb_root_execve_kernel(filename, envp_in);
}

static inline void ksu_static_branch_enable() { static_branch_enable(&ksu_adb_root_key); smp_mb(); }
static inline void ksu_static_branch_disable() { static_branch_disable(&ksu_adb_root_key); smp_mb(); }
#else /* ! KSU_CAN_USE_JUMP_LABEL */
static inline void ksu_adb_root_execve_user(void *restrict filename, void *restrict envp_in)
{
	if (unlikely(ksu_adb_root))
		do_ksu_adb_root_execve_user(filename, envp_in);
}
static inline void ksu_adb_root_execve_kernel(void *restrict filename, void *restrict envp_in)
{
	if (unlikely(ksu_adb_root))
		do_ksu_adb_root_execve_kernel(filename, envp_in);
}
static inline void ksu_static_branch_enable() { } // no-op
static inline void ksu_static_branch_disable() { } // no-op
#endif // KSU_CAN_USE_JUMP_LABEL

static int kernel_adb_root_feature_get(u64 *value)
{
	*value = ksu_adb_root ? 1 : 0;
	return 0;
}

static int kernel_adb_root_feature_set(u64 value)
{
	bool enable = value != 0;

	// prevent double enable / double disable
	// as old api does ref inc / dec, its a 'lil risky
	if (enable == ksu_adb_root)
		return 0;

	if (enable) {
		ksu_adb_root = true;
		ksu_static_branch_enable();
	} else {
		ksu_adb_root = false;
		ksu_static_branch_disable();
	}
	pr_info("adb_root: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler ksu_adb_root_handler = {
	.feature_id = KSU_FEATURE_ADB_ROOT,
	.name = "adb_root",
	.get_handler = kernel_adb_root_feature_get,
	.set_handler = kernel_adb_root_feature_set,
};

void __init ksu_adb_root_init(void)
{
	if (ksu_register_feature_handler(&ksu_adb_root_handler)) {
		pr_err("Failed to register adb_root feature handler\n");
	}
}

void __exit ksu_adb_root_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_ADB_ROOT);
}

#endif // CONFIG_KSU_FEATURE_ADBROOT
