#include "therm.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<linux/nvme_ioctl.h>)
#include <linux/nvme_ioctl.h>
#define AFR_HAVE_NVME_IOCTL 1
#endif
#endif

/* ---------- Governor ---------- */

void afr_gov_init(gov_t *g, int target)
{
	memset(g, 0, sizeof(*g));
	g->target = target;
	g->prev_temp = -1;
}

double afr_gov_step(gov_t *g, int temp, double measured_bps)
{
	const int tgt = g->target;
	const int rising = g->prev_temp >= 0 && temp > g->prev_temp;
	const int falling = g->prev_temp >= 0 && temp < g->prev_temp;
	g->prev_temp = temp;
	if (measured_bps > g->max_seen)
		g->max_seen = measured_bps;

	if (g->limit == 0) {
		/* Unlimited until the drive gets close to the target; then start from the rate
		 * it is reading at right now. */
		if (temp < tgt - 2)
			return 0;
		g->limit = measured_bps > GOV_MIN_RATE ? measured_bps : GOV_MIN_RATE;
	}
	/* The drive heats and cools over tens of seconds, so steps are small and react to
	 * the trend as well as to the level. */
	if (temp >= tgt + 1)
		g->limit *= 0.80;
	else if (temp >= tgt)
		g->limit *= 0.92;
	else if (temp == tgt - 1)
		g->limit *= rising ? 0.97 : 1.0;
	else if (temp == tgt - 2)
		g->limit *= rising ? 1.0 : 1.02;
	else
		g->limit *= falling ? 1.06 : 1.04;
	if (g->limit < GOV_MIN_RATE)
		g->limit = GOV_MIN_RATE;
	/* Well below the target and above anything the disk has done: lift the limit. */
	if (temp <= tgt - 4 && g->max_seen > 0 && g->limit > g->max_seen * 1.1)
		g->limit = 0;
	return g->limit;
}

/* ---------- Finding the drive ---------- */

static int read_line(const char *path, char *buf, size_t n)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	int ok = fgets(buf, (int)n, f) != NULL;
	fclose(f);
	if (!ok)
		return -1;
	buf[strcspn(buf, "\n")] = 0;
	return 0;
}

/* nvme0n1 -> nvme0 (controller of a namespace block device). */
static int nvme_controller(const char *disk, char *ctrl, size_t n)
{
	if (strncmp(disk, "nvme", 4) != 0)
		return -1;
	const char *p = disk + 4;
	size_t k = 0;
	while (isdigit((unsigned char)p[k]))
		k++;
	if (k == 0)
		return -1;
	snprintf(ctrl, n, "nvme%.*s", (int)k, p);
	return 0;
}

static void add_nvme(therm_dev_t *t, const char *disk)
{
	char ctrl[32];
	if (t->n >= THERM_MAX_DEVS || nvme_controller(disk, ctrl, sizeof(ctrl)) < 0)
		return;
	for (int i = 0; i < t->n; i++)
		if (!strcmp(t->name[i], ctrl))
			return;
	int i = t->n++;
	snprintf(t->name[i], sizeof(t->name[i]), "%s", ctrl);
	t->fd[i] = -1;
	t->hwmon[i][0] = 0;
	/* sysfs hwmon (newer kernels, readable without root) */
	char dir[256];
	snprintf(dir, sizeof(dir), "/sys/class/nvme/%s", ctrl);
	DIR *d = opendir(dir);
	if (d) {
		struct dirent *e;
		while ((e = readdir(d))) {
			if (strncmp(e->d_name, "hwmon", 5) == 0) {
				snprintf(t->hwmon[i], sizeof(t->hwmon[i]), "%s/%s/temp1_input", dir, e->d_name);
				break;
			}
		}
		closedir(d);
	}
	if (!t->hwmon[i][0]) {
		snprintf(dir, sizeof(dir), "/sys/class/nvme/%s/device/hwmon", ctrl);
		d = opendir(dir);
		if (d) {
			struct dirent *e;
			while ((e = readdir(d)))
				if (strncmp(e->d_name, "hwmon", 5) == 0) {
					snprintf(t->hwmon[i], sizeof(t->hwmon[i]), "%s/%s/temp1_input", dir,
					         e->d_name);
					break;
				}
			closedir(d);
		}
	}
	/* NVMe admin ioctl: works on old kernels too, needs root; also gives T1/T2 counters. */
	char devpath[64];
	snprintf(devpath, sizeof(devpath), "/dev/%s", ctrl);
	t->fd[i] = open(devpath, O_RDONLY | O_CLOEXEC);
}

/* Walk dm/md/LVM layers down to the physical disks. */
static void collect(therm_dev_t *t, const char *disk, int depth)
{
	if (depth > 8)
		return;
	if (strncmp(disk, "nvme", 4) == 0) {
		add_nvme(t, disk);
		return;
	}
	char dir[256];
	snprintf(dir, sizeof(dir), "/sys/block/%s/slaves", disk);
	DIR *d = opendir(dir);
	if (!d)
		return;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		/* a slave may be a partition: nvme0n1p2 -> its disk */
		char real[PATH_MAX], link[300], disk2[260];
		snprintf(link, sizeof(link), "/sys/class/block/%s", e->d_name);
		snprintf(disk2, sizeof(disk2), "%s", e->d_name);
		if (realpath(link, real)) {
			char part[PATH_MAX + 16];
			snprintf(part, sizeof(part), "%s/partition", real);
			if (access(part, F_OK) == 0) {
				char *slash = strrchr(real, '/');
				if (slash) {
					*slash = 0;
					char *b = strrchr(real, '/');
					if (b)
						snprintf(disk2, sizeof(disk2), "%s", b + 1);
				}
			}
		}
		collect(t, disk2, depth + 1);
	}
	closedir(d);
}

/* Block device of the mount holding path, from /proc/self/mountinfo (longest mount point
 * that is a prefix of the file's real path). */
static int mount_source_dev(const char *path, dev_t *dev)
{
	char rp[PATH_MAX];
	if (!realpath(path, rp))
		return -1;
	FILE *f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return -1;
	char line[4096], best_src[PATH_MAX] = "";
	size_t best_len = 0;
	while (fgets(line, sizeof(line), f)) {
		/* id parent major:minor root mountpoint options ... - fstype source superopts */
		char mnt[PATH_MAX], src[PATH_MAX];
		if (sscanf(line, "%*s %*s %*s %*s %4095s", mnt) != 1)
			continue;
		char *dash = strstr(line, " - ");
		if (!dash || sscanf(dash + 3, "%*s %4095s", src) != 1)
			continue;
		size_t ml = strlen(mnt);
		int prefix = strncmp(rp, mnt, ml) == 0 && (rp[ml] == '/' || rp[ml] == 0 || ml == 1);
		if (prefix && ml >= best_len && src[0] == '/') {
			best_len = ml;
			snprintf(best_src, sizeof(best_src), "%s", src);
		}
	}
	fclose(f);
	struct stat st;
	if (!best_src[0] || stat(best_src, &st) < 0 || !S_ISBLK(st.st_mode))
		return -1;
	*dev = st.st_rdev;
	return 0;
}

int afr_therm_open(therm_dev_t *t, const char *path, char *desc, size_t desclen)
{
	memset(t, 0, sizeof(*t));
	struct stat st;
	if (stat(path, &st) < 0) {
		snprintf(desc, desclen, "stat: %s", strerror(errno));
		return -1;
	}
	char link[128], real[PATH_MAX];
	snprintf(link, sizeof(link), "/sys/dev/block/%u:%u", major(st.st_dev), minor(st.st_dev));
	if (!realpath(link, real)) {
		/* btrfs and some others report an anonymous device number: take the block device
		 * the filesystem is mounted from instead. */
		dev_t bdev;
		if (mount_source_dev(path, &bdev) < 0) {
			snprintf(desc, desclen, "the file is not on a local block device");
			return -1;
		}
		snprintf(link, sizeof(link), "/sys/dev/block/%u:%u", major(bdev), minor(bdev));
		if (!realpath(link, real)) {
			snprintf(desc, desclen, "the file is not on a local block device");
			return -1;
		}
	}
	char part[PATH_MAX + 16];
	snprintf(part, sizeof(part), "%s/partition", real);
	if (access(part, F_OK) == 0) {
		char *slash = strrchr(real, '/');
		if (slash)
			*slash = 0;
	}
	const char *disk = strrchr(real, '/');
	disk = disk ? disk + 1 : real;
	collect(t, disk, 0);
	if (t->n == 0) {
		snprintf(desc, desclen, "%s is not on an NVMe drive", disk);
		return -1;
	}
	int temp;
	uint64_t thr;
	if (afr_therm_read(t, &temp, &thr) < 0) {
		snprintf(desc, desclen,
		         "cannot read the temperature of %s (no hwmon in sysfs; the NVMe ioctl needs root)",
		         t->name[0]);
		afr_therm_close(t);
		return -1;
	}
	size_t len = (size_t)snprintf(desc, desclen, "%s", t->name[0]);
	for (int i = 1; i < t->n && len < desclen; i++)
		len += (size_t)snprintf(desc + len, desclen - len, "+%s", t->name[i]);
	if (len < desclen)
		snprintf(desc + len, desclen - len, ", %d C%s", temp,
		         t->have_t1 ? ", throttling counters available" : "");
	return 0;
}

#ifdef AFR_HAVE_NVME_IOCTL
/* SMART / Health log (log page 0x02): composite temperature (K) at bytes 1-2, Thermal
 * Management T1/T2 transition counts at 216 and 220. */
static int smart_log(int fd, int *temp_c, uint64_t *thr)
{
	uint8_t log[512];
	struct nvme_admin_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	memset(log, 0, sizeof(log));
	cmd.opcode = 0x02;
	cmd.nsid = 0xffffffff;
	cmd.addr = (uint64_t)(uintptr_t)log;
	cmd.data_len = sizeof(log);
	cmd.cdw10 = 0x02 | ((uint32_t)(sizeof(log) / 4 - 1) << 16);
	if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0)
		return -1;
	int kelvin = log[1] | (log[2] << 8);
	if (kelvin == 0)
		return -1;
	*temp_c = kelvin - 273;
	uint32_t t1, t2;
	memcpy(&t1, log + 216, 4);
	memcpy(&t2, log + 220, 4);
	*thr = (uint64_t)t1 + t2;
	return 0;
}
#endif

int afr_therm_read(therm_dev_t *t, int *temp_c, uint64_t *throttle_count)
{
	int best = INT_MIN;
	uint64_t thr_sum = 0;
	int have_t1 = 0;
	for (int i = 0; i < t->n; i++) {
		int temp = INT_MIN;
#ifdef AFR_HAVE_NVME_IOCTL
		uint64_t thr;
		if (t->fd[i] >= 0 && smart_log(t->fd[i], &temp, &thr) == 0) {
			thr_sum += thr;
			have_t1 = 1;
		}
#endif
		if (temp == INT_MIN && t->hwmon[i][0]) {
			char buf[32];
			if (read_line(t->hwmon[i], buf, sizeof(buf)) == 0)
				temp = atoi(buf) / 1000;
		}
		if (temp > best)
			best = temp;
	}
	t->have_t1 = have_t1;
	if (best == INT_MIN)
		return -1;
	*temp_c = best;
	*throttle_count = thr_sum;
	return 0;
}

void afr_therm_close(therm_dev_t *t)
{
	for (int i = 0; i < t->n; i++)
		if (t->fd[i] >= 0)
			close(t->fd[i]);
	t->n = 0;
}

/* ---------- Monitor thread ---------- */

static void *mon_main(void *arg)
{
	therm_mon_t *m = arg;
	uint64_t last_bytes = m->bytes_read ? atomic_load(m->bytes_read) : 0;
	int64_t last_t = afr_now_ns();
	while (!atomic_load(&m->stop)) {
		struct timespec ts = {1, 0};
		nanosleep(&ts, NULL);
		int temp;
		uint64_t thr;
		if (afr_therm_read(&m->dev, &temp, &thr) < 0)
			continue;
		atomic_store(&m->temp, temp);
		if (temp > atomic_load(&m->max_temp))
			atomic_store(&m->max_temp, temp);
		atomic_store(&m->throttle, thr >= m->throttle0 ? thr - m->throttle0 : 0);
		int64_t now = afr_now_ns();
		uint64_t b = m->bytes_read ? atomic_load(m->bytes_read) : 0;
		double rate = (double)(b - last_bytes) * 1e9 / (double)(now - last_t);
		last_bytes = b;
		last_t = now;
		if (m->governor && m->rate_limit)
			atomic_store(m->rate_limit, (uint64_t)afr_gov_step(&m->gov, temp, rate));
	}
	return NULL;
}

int afr_therm_mon_start(therm_mon_t *m)
{
	int temp;
	uint64_t thr = 0;
	atomic_store(&m->temp, -1);
	atomic_store(&m->max_temp, -1);
	if (afr_therm_read(&m->dev, &temp, &thr) == 0) {
		atomic_store(&m->temp, temp);
		atomic_store(&m->max_temp, temp);
	}
	m->throttle0 = thr;
	atomic_store(&m->stop, 0);
	m->running = pthread_create(&m->th, NULL, mon_main, m) == 0;
	if (m->running)
		pthread_setname_np(m->th, "afr-therm");
	return m->running ? 0 : -1;
}

void afr_therm_mon_stop(therm_mon_t *m)
{
	if (!m->running)
		return;
	atomic_store(&m->stop, 1);
	pthread_join(m->th, NULL);
	m->running = 0;
}
