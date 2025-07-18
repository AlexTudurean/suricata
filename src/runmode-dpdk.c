/* Copyright (C) 2021-2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \ingroup dpdk
 *
 * @{
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 *
 * DPDK runmode
 *
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "runmode-dpdk.h"
#include "decode.h"
#include "source-dpdk.h"
#include "util-runmodes.h"
#include "util-byte.h"
#include "util-cpu.h"
#include "util-debug.h"
#include "util-device-private.h"
#include "util-dpdk.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-common.h"
#include "util-dpdk-i40e.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-ixgbe.h"
#include "util-dpdk-rss.h"
#include "util-time.h"
#include "util-conf.h"
#include "suricata.h"
#include "util-affinity.h"

#ifdef HAVE_DPDK

// Calculates the closest multiple of y from x
#define ROUNDUP(x, y) ((((x) + ((y)-1)) / (y)) * (y))

/* Maximum DPDK EAL parameters count. */
#define EAL_ARGS 48

struct Arguments {
    uint16_t capacity;
    char **argv;
    uint16_t argc;
};

static char *AllocArgument(size_t arg_len);
static char *AllocAndSetArgument(const char *arg);
static char *AllocAndSetOption(const char *arg);

static void ArgumentsInit(struct Arguments *args, uint16_t capacity);
static void ArgumentsCleanup(struct Arguments *args);
static void ArgumentsAdd(struct Arguments *args, char *value);
static void ArgumentsAddOptionAndArgument(struct Arguments *args, const char *opt, const char *arg);
static void InitEal(void);

static void ConfigSetIface(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetThreads(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetRxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues, uint16_t max_queues);
static int ConfigSetTxQueues(
        DPDKIfaceConfig *iconf, uint16_t nb_queues, uint16_t max_queues, bool iface_sends_pkts);
static int ConfigSetMempoolSize(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetMempoolCacheSize(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetRxDescriptors(DPDKIfaceConfig *iconf, const char *entry_str, uint16_t max_desc);
static int ConfigSetTxDescriptors(
        DPDKIfaceConfig *iconf, const char *entry_str, uint16_t max_desc, bool iface_sends_pkts);
static int ConfigSetMtu(DPDKIfaceConfig *iconf, intmax_t entry_int);
static bool ConfigSetPromiscuousMode(DPDKIfaceConfig *iconf, int entry_bool);
static bool ConfigSetMulticast(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetChecksumChecks(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetChecksumOffload(DPDKIfaceConfig *iconf, int entry_bool);
static int ConfigSetCopyIface(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetCopyMode(DPDKIfaceConfig *iconf, const char *entry_str);
static int ConfigSetCopyIfaceSettings(DPDKIfaceConfig *iconf, const char *iface, const char *mode);
static void ConfigInit(DPDKIfaceConfig **iconf);
static int ConfigLoad(DPDKIfaceConfig *iconf, const char *iface);
static DPDKIfaceConfig *ConfigParse(const char *iface);

static void DeviceInitPortConf(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf);
static int DeviceConfigureQueues(DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info,
        const struct rte_eth_conf *port_conf);
static int DeviceValidateOutIfaceConfig(DPDKIfaceConfig *iconf);
static int DeviceConfigureIPS(DPDKIfaceConfig *iconf);
static int DeviceConfigure(DPDKIfaceConfig *iconf);
static void *ParseDpdkConfigAndConfigureDevice(const char *iface);
static void DPDKDerefConfig(void *conf);

#define DPDK_CONFIG_DEFAULT_THREADS                     "auto"
#define DPDK_CONFIG_DEFAULT_INTERRUPT_MODE              false
#define DPDK_CONFIG_DEFAULT_MEMPOOL_SIZE                "auto"
#define DPDK_CONFIG_DEFAULT_MEMPOOL_CACHE_SIZE          "auto"
#define DPDK_CONFIG_DEFAULT_RX_DESCRIPTORS              "auto"
#define DPDK_CONFIG_DEFAULT_TX_DESCRIPTORS              "auto"
#define DPDK_CONFIG_DEFAULT_RSS_HASH_FUNCTIONS          RTE_ETH_RSS_IP
#define DPDK_CONFIG_DEFAULT_MTU                         1500
#define DPDK_CONFIG_DEFAULT_PROMISCUOUS_MODE            1
#define DPDK_CONFIG_DEFAULT_MULTICAST_MODE              1
#define DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION         1
#define DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION_OFFLOAD 1
#define DPDK_CONFIG_DEFAULT_VLAN_STRIP                  0
#define DPDK_CONFIG_DEFAULT_LINKUP_TIMEOUT              0
#define DPDK_CONFIG_DEFAULT_COPY_MODE                   "none"
#define DPDK_CONFIG_DEFAULT_COPY_INTERFACE              "none"

DPDKIfaceConfigAttributes dpdk_yaml = {
    .threads = "threads",
    .irq_mode = "interrupt-mode",
    .promisc = "promisc",
    .multicast = "multicast",
    .checksum_checks = "checksum-checks",
    .checksum_checks_offload = "checksum-checks-offload",
    .mtu = "mtu",
    .vlan_strip_offload = "vlan-strip-offload",
    .rss_hf = "rss-hash-functions",
    .linkup_timeout = "linkup-timeout",
    .mempool_size = "mempool-size",
    .mempool_cache_size = "mempool-cache-size",
    .rx_descriptors = "rx-descriptors",
    .tx_descriptors = "tx-descriptors",
    .copy_mode = "copy-mode",
    .copy_iface = "copy-iface",
};

/**
 * \brief Input is a number of which we want to find the greatest divisor up to max_num (inclusive).
 * The divisor is returned.
 */
static uint32_t GreatestDivisorUpTo(uint32_t num, uint32_t max_num)
{
    for (uint32_t i = max_num; i >= 2; i--) {
        if (num % i == 0) {
            return i;
        }
    }
    return 1;
}

/**
 * \brief Input is a number of which we want to find the greatest power of 2 up to num. The power of
 * 2 is returned or 0 if no valid power of 2 is found.
 */
static uint64_t GreatestPowOf2UpTo(uint64_t num)
{
    if (num == 0) {
        return 0; // No power of 2 exists for 0
    }

    // Bit manipulation to isolate the highest set bit
    num |= (num >> 1);
    num |= (num >> 2);
    num |= (num >> 4);
    num |= (num >> 8);
    num |= (num >> 16);
    num |= (num >> 32);
    num = num - (num >> 1);

    return num;
}

static char *AllocArgument(size_t arg_len)
{
    SCEnter();
    char *ptr;

    arg_len += 1; // null character
    ptr = (char *)SCCalloc(arg_len, sizeof(char));
    if (ptr == NULL)
        FatalError("Could not allocate memory for an argument");

    SCReturnPtr(ptr, "char *");
}

/**
 * Allocates space for length of the given string and then copies contents
 * @param arg String to set to the newly allocated space
 * @return memory address if no error otherwise NULL (with errno set)
 */
static char *AllocAndSetArgument(const char *arg)
{
    SCEnter();
    if (arg == NULL)
        FatalError("Passed argument is NULL in DPDK config initialization");

    char *ptr;
    size_t arg_len = strlen(arg);

    ptr = AllocArgument(arg_len);
    strlcpy(ptr, arg, arg_len + 1);
    SCReturnPtr(ptr, "char *");
}

static char *AllocAndSetOption(const char *arg)
{
    SCEnter();
    if (arg == NULL)
        FatalError("Passed option is NULL in DPDK config initialization");

    char *ptr = NULL;
    size_t arg_len = strlen(arg);
    uint8_t is_long_arg = arg_len > 1;
    const char *dash_prefix = is_long_arg ? "--" : "-";
    size_t full_len = arg_len + strlen(dash_prefix);

    ptr = AllocArgument(full_len);
    strlcpy(ptr, dash_prefix, full_len);
    strlcat(ptr, arg, full_len);
    SCReturnPtr(ptr, "char *");
}

static void ArgumentsInit(struct Arguments *args, uint16_t capacity)
{
    SCEnter();
    args->argv = SCCalloc(capacity, sizeof(*args->argv)); // alloc array of pointers
    if (args->argv == NULL)
        FatalError("Could not allocate memory for Arguments structure");

    args->capacity = capacity;
    args->argc = 0;
    SCReturn;
}

static void ArgumentsCleanup(struct Arguments *args)
{
    SCEnter();
    for (int i = 0; i < args->argc; i++) {
        if (args->argv[i] != NULL) {
            SCFree(args->argv[i]);
            args->argv[i] = NULL;
        }
    }

    SCFree(args->argv);
    args->argv = NULL;
    args->argc = 0;
    args->capacity = 0;
}

static void ArgumentsAdd(struct Arguments *args, char *value)
{
    SCEnter();
    if (args->argc + 1 > args->capacity)
        FatalError("No capacity for more arguments (Max: %" PRIu32 ")", EAL_ARGS);

    args->argv[args->argc++] = value;
    SCReturn;
}

static void ArgumentsAddOptionAndArgument(struct Arguments *args, const char *opt, const char *arg)
{
    SCEnter();
    char *option;
    char *argument;

    option = AllocAndSetOption(opt);
    ArgumentsAdd(args, option);

    // Empty argument could mean option only (e.g. --no-huge)
    if (arg == NULL || arg[0] == '\0')
        SCReturn;

    argument = AllocAndSetArgument(arg);
    ArgumentsAdd(args, argument);
    SCReturn;
}

static void InitEal(void)
{
    SCEnter();
    int retval;
    SCConfNode *param;
    const SCConfNode *eal_params = SCConfGetNode("dpdk.eal-params");
    struct Arguments args;
    char **eal_argv;

    if (eal_params == NULL) {
        FatalError("DPDK EAL parameters not found in the config");
    }

    ArgumentsInit(&args, EAL_ARGS);
    ArgumentsAdd(&args, AllocAndSetArgument("suricata"));

    TAILQ_FOREACH (param, &eal_params->head, next) {
        if (SCConfNodeIsSequence(param)) {
            const char *key = param->name;
            SCConfNode *val;
            TAILQ_FOREACH (val, &param->head, next) {
                ArgumentsAddOptionAndArgument(&args, key, (const char *)val->val);
            }
            continue;
        }
        ArgumentsAddOptionAndArgument(&args, param->name, param->val);
    }

    // creating a shallow copy for cleanup because rte_eal_init changes array contents
    eal_argv = SCCalloc(args.argc, sizeof(*args.argv));
    if (eal_argv == NULL) {
        FatalError("Failed to allocate memory for the array of DPDK EAL arguments");
    }
    memcpy(eal_argv, args.argv, args.argc * sizeof(*args.argv));

    rte_log_set_global_level(RTE_LOG_WARNING);
    retval = rte_eal_init(args.argc, eal_argv);

    ArgumentsCleanup(&args);
    SCFree(eal_argv);

    if (retval < 0) { // retval bound to the result of rte_eal_init
        FatalError("DPDK EAL initialization error: %s", rte_strerror(-retval));
    }
}

static void DPDKDerefConfig(void *conf)
{
    SCEnter();
    DPDKIfaceConfig *iconf = (DPDKIfaceConfig *)conf;

    if (SC_ATOMIC_SUB(iconf->ref, 1) == 1) {
        DPDKDeviceResourcesDeinit(&iconf->pkt_mempools);
        SCFree(iconf);
    }
    SCReturn;
}

static void ConfigInit(DPDKIfaceConfig **iconf)
{
    SCEnter();
    DPDKIfaceConfig *ptr = NULL;
    ptr = SCCalloc(1, sizeof(DPDKIfaceConfig));
    if (ptr == NULL)
        FatalError("Could not allocate memory for DPDKIfaceConfig");

    ptr->out_port_id = UINT16_MAX; // make sure no port is set
    SC_ATOMIC_INIT(ptr->ref);
    (void)SC_ATOMIC_ADD(ptr->ref, 1);
    ptr->DerefFunc = DPDKDerefConfig;
    ptr->flags = 0;

    *iconf = ptr;
    SCReturn;
}

static void ConfigSetIface(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    int retval;

    if (entry_str == NULL || entry_str[0] == '\0')
        FatalError("Interface name in DPDK config is NULL or empty");

    retval = rte_eth_dev_get_port_by_name(entry_str, &iconf->port_id);
    if (retval < 0)
        FatalError("%s: interface not found: %s", entry_str, rte_strerror(-retval));

    strlcpy(iconf->iface, entry_str, sizeof(iconf->iface));
    SCReturn;
}

static int ConfigSetThreads(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    static uint16_t remaining_auto_cpus = UINT16_MAX; // uninitialized
    if (!threading_set_cpu_affinity) {
        SCLogError("DPDK runmode requires configured thread affinity");
        SCReturnInt(-EINVAL);
    }

    bool wtaf_periface = true;
    ThreadsAffinityType *wtaf = GetAffinityTypeForNameAndIface("worker-cpu-set", iconf->iface);
    if (wtaf == NULL) {
        wtaf_periface = false;
        wtaf = GetAffinityTypeForNameAndIface("worker-cpu-set", NULL); // mandatory
        if (wtaf == NULL) {
            SCLogError("Specify worker-cpu-set list in the threading section");
            SCReturnInt(-EINVAL);
        }
    }
    ThreadsAffinityType *mtaf = GetAffinityTypeForNameAndIface("management-cpu-set", NULL);
    if (mtaf == NULL) {
        SCLogError("Specify management-cpu-set list in the threading section");
        SCReturnInt(-EINVAL);
    }
    uint16_t sched_cpus = UtilAffinityGetAffinedCPUNum(wtaf);
    if (sched_cpus == UtilCpuGetNumProcessorsOnline()) {
        SCLogWarning(
                "\"all\" specified in worker CPU cores affinity, excluding management threads");
        UtilAffinityCpusExclude(wtaf, mtaf);
        sched_cpus = UtilAffinityGetAffinedCPUNum(wtaf);
    }

    if (sched_cpus == 0) {
        SCLogError("No worker CPU cores with configured affinity were configured");
        SCReturnInt(-EINVAL);
    } else if (UtilAffinityCpusOverlap(wtaf, mtaf) != 0) {
        SCLogWarning("Worker threads should not overlap with management threads in the CPU core "
                     "affinity configuration");
    }

    const char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("single", active_runmode)) {
        iconf->threads = 1;
        SCReturnInt(0);
    }

    if (entry_str == NULL) {
        SCLogError("Number of threads for interface \"%s\" not specified", iconf->iface);
        SCReturnInt(-EINVAL);
    }

    if (strcmp(entry_str, "auto") == 0) {
        if (wtaf_periface) {
            iconf->threads = (uint16_t)sched_cpus;
            SCLogConfig("%s: auto-assigned %u threads", iconf->iface, iconf->threads);
            SCReturnInt(0);
        }

        uint16_t live_dev_count = (uint16_t)LiveGetDeviceCountWithoutAssignedThreading();
        if (live_dev_count == 0) {
            SCLogError("No live devices found, cannot auto-assign threads");
            SCReturnInt(-EINVAL);
        }
        iconf->threads = sched_cpus / live_dev_count;
        if (iconf->threads == 0) {
            SCLogError("Not enough worker CPU cores with affinity were configured");
            SCReturnInt(-ERANGE);
        }

        if (remaining_auto_cpus > 0) {
            iconf->threads++;
            remaining_auto_cpus--;
        } else if (remaining_auto_cpus == UINT16_MAX) {
            // first time auto-assignment
            remaining_auto_cpus = sched_cpus % live_dev_count;
            if (remaining_auto_cpus > 0) {
                iconf->threads++;
                remaining_auto_cpus--;
            }
        }
        SCLogConfig("%s: auto-assigned %u threads", iconf->iface, iconf->threads);
        SCReturnInt(0);
    }

    if (StringParseUint16(&iconf->threads, 10, 0, entry_str) < 0) {
        SCLogError("Threads entry for interface %s contain non-numerical characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (iconf->threads <= 0) {
        SCLogError("%s: positive number of threads required", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static bool ConfigSetInterruptMode(DPDKIfaceConfig *iconf, bool enable)
{
    SCEnter();
    if (enable)
        iconf->flags |= DPDK_IRQ_MODE;

    SCReturnBool(true);
}

static int ConfigSetRxQueues(DPDKIfaceConfig *iconf, uint16_t nb_queues, uint16_t max_queues)
{
    SCEnter();
    if (nb_queues == 0) {
        SCLogInfo("%s: positive number of RX queues is required", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    if (nb_queues > max_queues) {
        SCLogInfo("%s: number of RX queues cannot exceed %" PRIu16, iconf->iface, max_queues);
        SCReturnInt(-ERANGE);
    }

    iconf->nb_rx_queues = nb_queues;
    SCReturnInt(0);
}

static bool ConfigIfaceSendsPkts(const char *mode)
{
    SCEnter();
    if (strcmp(mode, "ips") == 0 || strcmp(mode, "tap") == 0) {
        SCReturnBool(true);
    }
    SCReturnBool(false);
}

static int ConfigSetTxQueues(
        DPDKIfaceConfig *iconf, uint16_t nb_queues, uint16_t max_queues, bool iface_sends_pkts)
{
    SCEnter();
    if (nb_queues == 0 && iface_sends_pkts) {
        SCLogInfo("%s: positive number of TX queues is required", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    if (nb_queues > max_queues) {
        SCLogInfo("%s: number of TX queues cannot exceed %" PRIu16, iconf->iface, max_queues);
        SCReturnInt(-ERANGE);
    }

    iconf->nb_tx_queues = nb_queues;
    SCReturnInt(0);
}

static uint32_t MempoolSizeCalculate(
        uint32_t rx_queues, uint32_t rx_desc, uint32_t tx_queues, uint32_t tx_desc)
{
    uint32_t sz = rx_queues * rx_desc + tx_queues * tx_desc;
    if (!tx_queues || !tx_desc)
        sz *= 2; // double to have enough space for RX descriptors

    return sz;
}

static int ConfigSetMempoolSize(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "auto") == 0) {
        // calculate the mempool size based on the number of:
        //   - RX / TX queues
        //   - RX / TX descriptors
        bool err = false;
        if (iconf->nb_rx_queues == 0) {
            // in IDS mode, we don't need TX queues
            SCLogError("%s: cannot autocalculate mempool size without RX queues", iconf->iface);
            err = true;
        }

        if (iconf->nb_rx_desc == 0) {
            SCLogError(
                    "%s: cannot autocalculate mempool size without RX descriptors", iconf->iface);
            err = true;
        }

        if (err) {
            SCReturnInt(-EINVAL);
        }

        iconf->mempool_size = MempoolSizeCalculate(
                iconf->nb_rx_queues, iconf->nb_rx_desc, iconf->nb_tx_queues, iconf->nb_tx_desc);
        SCReturnInt(0);
    }

    if (StringParseUint32(&iconf->mempool_size, 10, 0, entry_str) < 0) {
        SCLogError("%s: mempool size entry contain non-numerical characters - \"%s\"", iconf->iface,
                entry_str);
        SCReturnInt(-EINVAL);
    }

    if (MempoolSizeCalculate(
                iconf->nb_rx_queues, iconf->nb_rx_desc, iconf->nb_tx_queues, iconf->nb_tx_desc) >
            iconf->mempool_size + 1) { // +1 to mask mempool size advice given in Suricata 7.0.x -
                                       // mp_size should be n = (2^q - 1)
        SCLogError("%s: mempool size is likely too small for the number of descriptors and queues, "
                   "set to \"auto\" or adjust to the value of \"%" PRIu32 "\"",
                iconf->iface,
                MempoolSizeCalculate(iconf->nb_rx_queues, iconf->nb_rx_desc, iconf->nb_tx_queues,
                        iconf->nb_tx_desc));
        SCReturnInt(-ERANGE);
    }

    if (iconf->mempool_size == 0) {
        SCLogError("%s: mempool size requires a positive integer", iconf->iface);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static uint32_t MempoolCacheSizeCalculate(uint32_t mp_sz)
{
    // It is advised to have mempool cache size lower or equal to:
    //   RTE_MEMPOOL_CACHE_MAX_SIZE (by default 512) and "mempool-size / 1.5"
    // and at the same time "mempool-size modulo cache_size == 0".
    uint32_t max_cache_size = MIN(RTE_MEMPOOL_CACHE_MAX_SIZE, (uint32_t)(mp_sz / 1.5));
    return GreatestDivisorUpTo(mp_sz, max_cache_size);
}

static int ConfigSetMempoolCacheSize(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "auto") == 0) {
        // calculate the mempool size based on the mempool size (it needs to be already filled in)
        if (iconf->mempool_size == 0) {
            SCLogError("%s: cannot calculate mempool cache size of a mempool with size %d",
                    iconf->iface, iconf->mempool_size);
            SCReturnInt(-EINVAL);
        }

        iconf->mempool_cache_size = MempoolCacheSizeCalculate(iconf->mempool_size);
        SCReturnInt(0);
    }

    if (StringParseUint32(&iconf->mempool_cache_size, 10, 0, entry_str) < 0) {
        SCLogError("%s: mempool cache size entry contain non-numerical characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (iconf->mempool_cache_size <= 0 || iconf->mempool_cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE) {
        SCLogError("%s: mempool cache size requires a positive number smaller than %" PRIu32,
                iconf->iface, RTE_MEMPOOL_CACHE_MAX_SIZE);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetRxDescriptors(DPDKIfaceConfig *iconf, const char *entry_str, uint16_t max_desc)
{
    SCEnter();
    if (entry_str == NULL || entry_str[0] == '\0') {
        SCLogInfo("%s: number of RX descriptors not found, going with: %s", iconf->iface,
                DPDK_CONFIG_DEFAULT_RX_DESCRIPTORS);
        entry_str = DPDK_CONFIG_DEFAULT_RX_DESCRIPTORS;
    }

    if (strcmp(entry_str, "auto") == 0) {
        iconf->nb_rx_desc = (uint16_t)GreatestPowOf2UpTo(max_desc);
        SCReturnInt(0);
    }

    if (StringParseUint16(&iconf->nb_rx_desc, 10, 0, entry_str) < 0) {
        SCLogError("%s: RX descriptors entry contains non-numerical characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (iconf->nb_rx_desc == 0) {
        SCLogError("%s: positive number of RX descriptors is required", iconf->iface);
        SCReturnInt(-ERANGE);
    } else if (iconf->nb_rx_desc > max_desc) {
        SCLogError("%s: number of RX descriptors cannot exceed %" PRIu16, iconf->iface, max_desc);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetTxDescriptors(
        DPDKIfaceConfig *iconf, const char *entry_str, uint16_t max_desc, bool iface_sends_pkts)
{
    SCEnter();
    if (entry_str == NULL || entry_str[0] == '\0') {
        SCLogInfo("%s: number of TX descriptors not found, going with: %s", iconf->iface,
                DPDK_CONFIG_DEFAULT_TX_DESCRIPTORS);
        entry_str = DPDK_CONFIG_DEFAULT_TX_DESCRIPTORS;
    }

    if (strcmp(entry_str, "auto") == 0) {
        if (iface_sends_pkts) {
            iconf->nb_tx_desc = (uint16_t)GreatestPowOf2UpTo(max_desc);
        } else {
            iconf->nb_tx_desc = 0;
        }
        SCReturnInt(0);
    }

    if (StringParseUint16(&iconf->nb_tx_desc, 10, 0, entry_str) < 0) {
        SCLogError("%s: TX descriptors entry contains non-numerical characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    if (iconf->nb_tx_desc == 0 && iface_sends_pkts) {
        SCLogError("%s: positive number of TX descriptors is required", iconf->iface);
        SCReturnInt(-ERANGE);
    } else if (iconf->nb_tx_desc > max_desc) {
        SCLogError("%s: number of TX descriptors cannot exceed %" PRIu16, iconf->iface, max_desc);
        SCReturnInt(-ERANGE);
    }

    SCReturnInt(0);
}

static int ConfigSetRSSHashFunctions(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "auto") == 0) {
        iconf->rss_hf = DPDK_CONFIG_DEFAULT_RSS_HASH_FUNCTIONS;
        SCReturnInt(0);
    }

    if (StringParseUint64(&iconf->rss_hf, 0, 0, entry_str) < 0) {
        SCLogError("%s: RSS hash functions entry contain non-numerical characters - \"%s\"",
                iconf->iface, entry_str);
        SCReturnInt(-EINVAL);
    }

    SCReturnInt(0);
}

static int ConfigSetMtu(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int < RTE_ETHER_MIN_MTU || entry_int > RTE_ETHER_MAX_JUMBO_FRAME_LEN) {
        SCLogError("%s: MTU size can only be between %" PRIu32 " and %" PRIu32, iconf->iface,
                RTE_ETHER_MIN_MTU, RTE_ETHER_MAX_JUMBO_FRAME_LEN);
        SCReturnInt(-ERANGE);
    }

    iconf->mtu = (uint16_t)entry_int;
    SCReturnInt(0);
}

static int ConfigSetLinkupTimeout(DPDKIfaceConfig *iconf, intmax_t entry_int)
{
    SCEnter();
    if (entry_int < 0 || entry_int > UINT16_MAX) {
        SCLogError("%s: Link-up waiting timeout needs to be a positive number (up to %u) or 0 to "
                   "disable",
                iconf->iface, UINT16_MAX);
        SCReturnInt(-ERANGE);
    }

    iconf->linkup_timeout = (uint16_t)entry_int;
    SCReturnInt(0);
}

static bool ConfigSetPromiscuousMode(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->flags |= DPDK_PROMISC;

    SCReturnBool(true);
}

static bool ConfigSetMulticast(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->flags |= DPDK_MULTICAST; // enable

    SCReturnBool(true);
}

static int ConfigSetChecksumChecks(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;

    SCReturnInt(0);
}

static int ConfigSetChecksumOffload(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    if (entry_bool)
        iconf->flags |= DPDK_RX_CHECKSUM_OFFLOAD;

    SCReturnInt(0);
}

static void ConfigSetVlanStrip(DPDKIfaceConfig *iconf, int entry_bool)
{
    SCEnter();
    iconf->vlan_strip_enabled = entry_bool;
    SCReturn;
}

static int ConfigSetCopyIface(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    int retval;

    if (entry_str == NULL || entry_str[0] == '\0' || strcmp(entry_str, "none") == 0) {
        iconf->out_iface = NULL;
        SCReturnInt(0);
    }

    retval = rte_eth_dev_get_port_by_name(entry_str, &iconf->out_port_id);
    if (retval < 0) {
        SCLogError("%s: copy interface (%s) not found: %s", iconf->iface, entry_str,
                rte_strerror(-retval));
        SCReturnInt(retval);
    }

    iconf->out_iface = entry_str;
    SCReturnInt(0);
}

static int ConfigSetCopyMode(DPDKIfaceConfig *iconf, const char *entry_str)
{
    SCEnter();
    if (entry_str == NULL) {
        SCLogWarning("%s: no copy mode specified, changing to %s ", iconf->iface,
                DPDK_CONFIG_DEFAULT_COPY_MODE);
        entry_str = DPDK_CONFIG_DEFAULT_COPY_MODE;
    }

    if (strcmp(entry_str, "none") != 0 && strcmp(entry_str, "tap") != 0 &&
            strcmp(entry_str, "ips") != 0) {
        SCLogWarning("%s: copy mode \"%s\" is not one of the possible values (none|tap|ips). "
                     "Changing to %s",
                entry_str, iconf->iface, DPDK_CONFIG_DEFAULT_COPY_MODE);
        entry_str = DPDK_CONFIG_DEFAULT_COPY_MODE;
    }

    if (strcmp(entry_str, "none") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_NONE;
    } else if (strcmp(entry_str, "tap") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_TAP;
    } else if (strcmp(entry_str, "ips") == 0) {
        iconf->copy_mode = DPDK_COPY_MODE_IPS;
    }

    SCReturnInt(0);
}

static int ConfigSetCopyIfaceSettings(DPDKIfaceConfig *iconf, const char *iface, const char *mode)
{
    SCEnter();
    int retval;

    retval = ConfigSetCopyIface(iconf, iface);
    if (retval < 0)
        SCReturnInt(retval);

    retval = ConfigSetCopyMode(iconf, mode);
    if (retval < 0)
        SCReturnInt(retval);

    if (iconf->copy_mode == DPDK_COPY_MODE_NONE) {
        if (iconf->out_iface != NULL)
            iconf->out_iface = NULL;
        SCReturnInt(0);
    }

    if (iconf->out_iface == NULL || strlen(iconf->out_iface) <= 0) {
        SCLogError("%s: copy mode enabled but interface not set", iconf->iface);
        SCReturnInt(-EINVAL);
    }

    SCReturnInt(0);
}

static int ConfigLoad(DPDKIfaceConfig *iconf, const char *iface)
{
    SCEnter();
    int retval;
    SCConfNode *if_root;
    SCConfNode *if_default;
    const char *entry_str = NULL;
    intmax_t entry_int = 0;
    int entry_bool = 0;
    const char *copy_iface_str = NULL;
    const char *copy_mode_str = NULL;

    ConfigSetIface(iconf, iface);
    struct rte_eth_dev_info dev_info = { 0 };
    retval = rte_eth_dev_info_get(iconf->port_id, &dev_info);
    if (retval < 0) {
        SCLogError("%s: getting device info failed: %s", iconf->iface, rte_strerror(-retval));
        SCReturnInt(retval);
    }

    retval = SCConfSetRootAndDefaultNodes("dpdk.interfaces", iconf->iface, &if_root, &if_default);
    if (retval < 0) {
        FatalError("failed to find DPDK configuration for the interface %s", iconf->iface);
    }

    retval = SCConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.threads, &entry_str) != 1
                     ? ConfigSetThreads(iconf, DPDK_CONFIG_DEFAULT_THREADS)
                     : ConfigSetThreads(iconf, entry_str);
    if (retval < 0)
        SCReturnInt(retval);

    bool irq_enable;
    retval = SCConfGetChildValueBoolWithDefault(
            if_root, if_default, dpdk_yaml.irq_mode, &entry_bool);
    if (retval != 1) {
        irq_enable = DPDK_CONFIG_DEFAULT_INTERRUPT_MODE;
    } else {
        irq_enable = entry_bool ? true : false;
    }
    retval = ConfigSetInterruptMode(iconf, irq_enable);
    if (retval != true)
        SCReturnInt(-EINVAL);

    retval = SCConfGetChildValueWithDefault(
            if_root, if_default, dpdk_yaml.copy_mode, &copy_mode_str);
    if (retval != 1) {
        copy_mode_str = DPDK_CONFIG_DEFAULT_COPY_MODE;
    }

    retval = SCConfGetChildValueWithDefault(
                     if_root, if_default, dpdk_yaml.rx_descriptors, &entry_str) != 1
                     ? ConfigSetRxDescriptors(iconf, DPDK_CONFIG_DEFAULT_RX_DESCRIPTORS,
                               dev_info.rx_desc_lim.nb_max)
                     : ConfigSetRxDescriptors(iconf, entry_str, dev_info.rx_desc_lim.nb_max);
    if (retval < 0)
        SCReturnInt(retval);

    bool iface_sends_pkts = ConfigIfaceSendsPkts(copy_mode_str);
    retval = SCConfGetChildValueWithDefault(
                     if_root, if_default, dpdk_yaml.tx_descriptors, &entry_str) != 1
                     ? ConfigSetTxDescriptors(iconf, DPDK_CONFIG_DEFAULT_TX_DESCRIPTORS,
                               dev_info.tx_desc_lim.nb_max, iface_sends_pkts)
                     : ConfigSetTxDescriptors(
                               iconf, entry_str, dev_info.tx_desc_lim.nb_max, iface_sends_pkts);
    if (retval < 0)
        SCReturnInt(retval);

    // currently only mapping "1 thread == 1 RX (and 1 TX queue in IPS mode)" is supported
    retval = ConfigSetRxQueues(iconf, iconf->threads, dev_info.max_rx_queues);
    if (retval < 0) {
        SCLogError("%s: too many threads configured - reduce thread count to: %" PRIu16,
                iconf->iface, dev_info.max_rx_queues);
        SCReturnInt(retval);
    }

    // currently only mapping "1 thread == 1 RX (and 1 TX queue in IPS mode)" is supported
    uint16_t tx_queues = iconf->nb_tx_desc > 0 ? iconf->threads : 0;
    retval = ConfigSetTxQueues(iconf, tx_queues, dev_info.max_tx_queues, iface_sends_pkts);
    if (retval < 0) {
        SCLogError("%s: too many threads configured - reduce thread count to: %" PRIu16,
                iconf->iface, dev_info.max_tx_queues);
        SCReturnInt(retval);
    }

    retval = SCConfGetChildValueWithDefault(
                     if_root, if_default, dpdk_yaml.mempool_size, &entry_str) != 1
                     ? ConfigSetMempoolSize(iconf, DPDK_CONFIG_DEFAULT_MEMPOOL_SIZE)
                     : ConfigSetMempoolSize(iconf, entry_str);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueWithDefault(
                     if_root, if_default, dpdk_yaml.mempool_cache_size, &entry_str) != 1
                     ? ConfigSetMempoolCacheSize(iconf, DPDK_CONFIG_DEFAULT_MEMPOOL_CACHE_SIZE)
                     : ConfigSetMempoolCacheSize(iconf, entry_str);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueIntWithDefault(if_root, if_default, dpdk_yaml.mtu, &entry_int) != 1
                     ? ConfigSetMtu(iconf, DPDK_CONFIG_DEFAULT_MTU)
                     : ConfigSetMtu(iconf, entry_int);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueWithDefault(if_root, if_default, dpdk_yaml.rss_hf, &entry_str) != 1
                     ? ConfigSetRSSHashFunctions(iconf, NULL)
                     : ConfigSetRSSHashFunctions(iconf, entry_str);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.promisc, &entry_bool) != 1
                     ? ConfigSetPromiscuousMode(iconf, DPDK_CONFIG_DEFAULT_PROMISCUOUS_MODE)
                     : ConfigSetPromiscuousMode(iconf, entry_bool);
    if (retval != true)
        SCReturnInt(-EINVAL);

    retval = SCConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.multicast, &entry_bool) != 1
                     ? ConfigSetMulticast(iconf, DPDK_CONFIG_DEFAULT_MULTICAST_MODE)
                     : ConfigSetMulticast(iconf, entry_bool);
    if (retval != true)
        SCReturnInt(-EINVAL);

    retval = SCConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.checksum_checks, &entry_bool) != 1
                     ? ConfigSetChecksumChecks(iconf, DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION)
                     : ConfigSetChecksumChecks(iconf, entry_bool);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueBoolWithDefault(
                     if_root, if_default, dpdk_yaml.checksum_checks_offload, &entry_bool) != 1
                     ? ConfigSetChecksumOffload(
                               iconf, DPDK_CONFIG_DEFAULT_CHECKSUM_VALIDATION_OFFLOAD)
                     : ConfigSetChecksumOffload(iconf, entry_bool);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueBoolWithDefault(
            if_root, if_default, dpdk_yaml.vlan_strip_offload, &entry_bool);
    if (retval != 1) {
        ConfigSetVlanStrip(iconf, DPDK_CONFIG_DEFAULT_VLAN_STRIP);
    } else {
        ConfigSetVlanStrip(iconf, entry_bool);
    }

    retval = SCConfGetChildValueIntWithDefault(
                     if_root, if_default, dpdk_yaml.linkup_timeout, &entry_int) != 1
                     ? ConfigSetLinkupTimeout(iconf, DPDK_CONFIG_DEFAULT_LINKUP_TIMEOUT)
                     : ConfigSetLinkupTimeout(iconf, entry_int);
    if (retval < 0)
        SCReturnInt(retval);

    retval = SCConfGetChildValueWithDefault(
            if_root, if_default, dpdk_yaml.copy_iface, &copy_iface_str);
    if (retval != 1) {
        copy_iface_str = DPDK_CONFIG_DEFAULT_COPY_INTERFACE;
    }

    retval = ConfigSetCopyIfaceSettings(iconf, copy_iface_str, copy_mode_str);
    if (retval < 0)
        SCReturnInt(retval);

    SCReturnInt(0);
}

static bool ConfigThreadsGenericIsValid(uint16_t iface_threads, ThreadsAffinityType *wtaf)
{
    static uint32_t total_cpus = 0;
    total_cpus += iface_threads;
    if (wtaf == NULL) {
        SCLogError("Specify worker-cpu-set list in the threading section");
        return false;
    }
    if (total_cpus > UtilAffinityGetAffinedCPUNum(wtaf)) {
        SCLogError("Interfaces requested more cores than configured in the worker-cpu-set "
                   "threading section (requested %d configured %d",
                total_cpus, UtilAffinityGetAffinedCPUNum(wtaf));
        return false;
    }

    return true;
}

static bool ConfigThreadsInterfaceIsValid(uint16_t iface_threads, ThreadsAffinityType *itaf)
{
    if (iface_threads > UtilAffinityGetAffinedCPUNum(itaf)) {
        SCLogError("Interface requested more cores than configured in the interface-specific "
                   "threading section (requested %d configured %d",
                iface_threads, UtilAffinityGetAffinedCPUNum(itaf));
        return false;
    }

    return true;
}

static bool ConfigIsThreadingValid(uint16_t iface_threads, const char *iface)
{
    ThreadsAffinityType *itaf = GetAffinityTypeForNameAndIface("worker-cpu-set", iface);
    ThreadsAffinityType *wtaf = GetAffinityTypeForNameAndIface("worker-cpu-set", NULL);
    if (itaf && !ConfigThreadsInterfaceIsValid(iface_threads, itaf)) {
        return false;
    } else if (itaf == NULL && !ConfigThreadsGenericIsValid(iface_threads, wtaf)) {
        return false;
    }
    return true;
}

static DPDKIfaceConfig *ConfigParse(const char *iface)
{
    SCEnter();
    int retval;
    DPDKIfaceConfig *iconf = NULL;
    if (iface == NULL)
        FatalError("DPDK interface is NULL");

    ConfigInit(&iconf);
    retval = ConfigLoad(iconf, iface);
    if (retval < 0 || !ConfigIsThreadingValid(iconf->threads, iface)) {
        iconf->DerefFunc(iconf);
        SCReturnPtr(NULL, "void *");
    }

    SCReturnPtr(iconf, "DPDKIfaceConfig *");
}

static void DeviceSetPMDSpecificRSS(struct rte_eth_rss_conf *rss_conf, const char *driver_name)
{
    if (strcmp(driver_name, "net_i40e") == 0)
        i40eDeviceSetRSSConf(rss_conf);
    if (strcmp(driver_name, "net_ice") == 0)
        iceDeviceSetRSSConf(rss_conf);
    if (strcmp(driver_name, "net_ixgbe") == 0)
        ixgbeDeviceSetRSSHashFunction(&rss_conf->rss_hf);
    if (strcmp(driver_name, "net_e1000_igb") == 0)
        rss_conf->rss_hf = (RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_IPV6_EX);
}

// Returns -1 if no bit is set
static int32_t GetFirstSetBitPosition(uint64_t bits)
{
    for (int32_t i = 0; i < 64; i++) {
        if (bits & BIT_U64(i))
            return i;
    }
    return -1;
}

static void DumpRSSFlags(const uint64_t requested, const uint64_t actual)
{
    SCLogConfig("REQUESTED (groups):");

    SCLogConfig(
            "RTE_ETH_RSS_IP %sset", ((requested & RTE_ETH_RSS_IP) == RTE_ETH_RSS_IP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_TCP %sset",
            ((requested & RTE_ETH_RSS_TCP) == RTE_ETH_RSS_TCP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_UDP %sset",
            ((requested & RTE_ETH_RSS_UDP) == RTE_ETH_RSS_UDP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_SCTP %sset",
            ((requested & RTE_ETH_RSS_SCTP) == RTE_ETH_RSS_SCTP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_TUNNEL %sset",
            ((requested & RTE_ETH_RSS_TUNNEL) == RTE_ETH_RSS_TUNNEL) ? "" : "NOT ");

    SCLogConfig("REQUESTED (individual):");
    SCLogConfig("RTE_ETH_RSS_IPV4 (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_IPV4), (requested & RTE_ETH_RSS_IPV4) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_FRAG_IPV4 (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_FRAG_IPV4),
            (requested & RTE_ETH_RSS_FRAG_IPV4) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_TCP (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV4_TCP),
            (requested & RTE_ETH_RSS_NONFRAG_IPV4_TCP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_UDP (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV4_UDP),
            (requested & RTE_ETH_RSS_NONFRAG_IPV4_UDP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_SCTP (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV4_SCTP),
            (requested & RTE_ETH_RSS_NONFRAG_IPV4_SCTP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_OTHER (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV4_OTHER),
            (requested & RTE_ETH_RSS_NONFRAG_IPV4_OTHER) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6 (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_IPV6), (requested & RTE_ETH_RSS_IPV6) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_FRAG_IPV6 (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_FRAG_IPV6),
            (requested & RTE_ETH_RSS_FRAG_IPV6) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_TCP (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV6_TCP),
            (requested & RTE_ETH_RSS_NONFRAG_IPV6_TCP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_UDP (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV6_UDP),
            (requested & RTE_ETH_RSS_NONFRAG_IPV6_UDP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_SCTP (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV6_SCTP),
            (requested & RTE_ETH_RSS_NONFRAG_IPV6_SCTP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_OTHER (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NONFRAG_IPV6_OTHER),
            (requested & RTE_ETH_RSS_NONFRAG_IPV6_OTHER) ? "" : "NOT ");

    SCLogConfig("RTE_ETH_RSS_L2_PAYLOAD (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_L2_PAYLOAD),
            (requested & RTE_ETH_RSS_L2_PAYLOAD) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6_EX (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_IPV6_EX),
            (requested & RTE_ETH_RSS_IPV6_EX) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6_TCP_EX (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_IPV6_TCP_EX),
            (requested & RTE_ETH_RSS_IPV6_TCP_EX) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6_UDP_EX (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_IPV6_UDP_EX),
            (requested & RTE_ETH_RSS_IPV6_UDP_EX) ? "" : "NOT ");

    SCLogConfig("RTE_ETH_RSS_PORT (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_PORT), (requested & RTE_ETH_RSS_PORT) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_VXLAN (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_VXLAN),
            (requested & RTE_ETH_RSS_VXLAN) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NVGRE (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_NVGRE),
            (requested & RTE_ETH_RSS_NVGRE) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_GTPU (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_GTPU), (requested & RTE_ETH_RSS_GTPU) ? "" : "NOT ");

    SCLogConfig("RTE_ETH_RSS_L3_SRC_ONLY (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_L3_SRC_ONLY),
            (requested & RTE_ETH_RSS_L3_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_L3_DST_ONLY (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_L3_DST_ONLY),
            (requested & RTE_ETH_RSS_L3_DST_ONLY) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_L4_SRC_ONLY (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_L4_SRC_ONLY),
            (requested & RTE_ETH_RSS_L4_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_L4_DST_ONLY (Bit position: %d) %sset",
            GetFirstSetBitPosition(RTE_ETH_RSS_L4_DST_ONLY),
            (requested & RTE_ETH_RSS_L4_DST_ONLY) ? "" : "NOT ");
    SCLogConfig("ACTUAL (group):");
    SCLogConfig(
            "RTE_ETH_RSS_IP %sset", ((actual & RTE_ETH_RSS_IP) == RTE_ETH_RSS_IP) ? "" : "NOT ");
    SCLogConfig(
            "RTE_ETH_RSS_TCP %sset", ((actual & RTE_ETH_RSS_TCP) == RTE_ETH_RSS_TCP) ? "" : "NOT ");
    SCLogConfig(
            "RTE_ETH_RSS_UDP %sset", ((actual & RTE_ETH_RSS_UDP) == RTE_ETH_RSS_UDP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_SCTP %sset",
            ((actual & RTE_ETH_RSS_SCTP) == RTE_ETH_RSS_SCTP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_TUNNEL %sset",
            ((actual & RTE_ETH_RSS_TUNNEL) == RTE_ETH_RSS_TUNNEL) ? "" : "NOT ");

    SCLogConfig("ACTUAL (individual flags):");
    SCLogConfig("RTE_ETH_RSS_IPV4 %sset", (actual & RTE_ETH_RSS_IPV4) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_FRAG_IPV4 %sset", (actual & RTE_ETH_RSS_FRAG_IPV4) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_TCP %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV4_TCP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_UDP %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV4_UDP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_SCTP %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV4_SCTP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV4_OTHER %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV4_OTHER) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6 %sset", (actual & RTE_ETH_RSS_IPV6) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_FRAG_IPV6 %sset", (actual & RTE_ETH_RSS_FRAG_IPV6) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_TCP %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV6_TCP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_UDP %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV6_UDP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_SCTP %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV6_SCTP) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NONFRAG_IPV6_OTHER %sset",
            (actual & RTE_ETH_RSS_NONFRAG_IPV6_OTHER) ? "" : "NOT ");

    SCLogConfig("RTE_ETH_RSS_L2_PAYLOAD %sset", (actual & RTE_ETH_RSS_L2_PAYLOAD) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6_EX %sset", (actual & RTE_ETH_RSS_IPV6_EX) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6_TCP_EX %sset", (actual & RTE_ETH_RSS_IPV6_TCP_EX) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_IPV6_UDP_EX %sset", (actual & RTE_ETH_RSS_IPV6_UDP_EX) ? "" : "NOT ");

    SCLogConfig("RTE_ETH_RSS_PORT %sset", (actual & RTE_ETH_RSS_PORT) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_VXLAN %sset", (actual & RTE_ETH_RSS_VXLAN) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_NVGRE %sset", (actual & RTE_ETH_RSS_NVGRE) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_GTPU %sset", (actual & RTE_ETH_RSS_GTPU) ? "" : "NOT ");

    SCLogConfig("RTE_ETH_RSS_L3_SRC_ONLY %sset", (actual & RTE_ETH_RSS_L3_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_L3_DST_ONLY %sset", (actual & RTE_ETH_RSS_L3_DST_ONLY) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_L4_SRC_ONLY %sset", (actual & RTE_ETH_RSS_L4_SRC_ONLY) ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RSS_L4_DST_ONLY %sset", (actual & RTE_ETH_RSS_L4_DST_ONLY) ? "" : "NOT ");
}

static void DumpRXOffloadCapabilities(const uint64_t rx_offld_capa)
{
    SCLogConfig("RTE_ETH_RX_OFFLOAD_VLAN_STRIP - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_IPV4_CKSUM - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_UDP_CKSUM - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_TCP_CKSUM - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_TCP_LRO - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_QINQ_STRIP - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_QINQ_STRIP ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_MACSEC_STRIP - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_MACSEC_STRIP ? "" : "NOT ");
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
    SCLogConfig("RTE_ETH_RX_OFFLOAD_HEADER_SPLIT - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_HEADER_SPLIT ? "" : "NOT ");
#endif
    SCLogConfig("RTE_ETH_RX_OFFLOAD_VLAN_FILTER - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_VLAN_FILTER ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_VLAN_EXTEND - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_VLAN_EXTEND ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_SCATTER - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_SCATTER ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_TIMESTAMP - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_SECURITY - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_SECURITY ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_KEEP_CRC - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_KEEP_CRC ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_SCTP_CKSUM - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_SCTP_CKSUM ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM ? "" : "NOT ");
    SCLogConfig("RTE_ETH_RX_OFFLOAD_RSS_HASH - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_RSS_HASH ? "" : "NOT ");
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
    SCLogConfig("RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT - %savailable",
            rx_offld_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT ? "" : "NOT ");
#endif
}

static int DeviceValidateMTU(const DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info)
{
    SCEnter();
    if (iconf->mtu > dev_info->max_mtu || iconf->mtu < dev_info->min_mtu) {
        SCLogError("%s: MTU out of bounds. "
                   "Min MTU: %" PRIu16 " Max MTU: %" PRIu16,
                iconf->iface, dev_info->min_mtu, dev_info->max_mtu);
        SCReturnInt(-ERANGE);
    }

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
    // check if jumbo frames are set and are available
    if (iconf->mtu > RTE_ETHER_MAX_LEN &&
            !(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME)) {
        SCLogError("%s: jumbo frames not supported, set MTU to 1500", iconf->iface);
        SCReturnInt(-EINVAL);
    }
#endif

    SCReturnInt(0);
}

static void DeviceSetMTU(struct rte_eth_conf *port_conf, uint16_t mtu)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
    port_conf->rxmode.mtu = mtu;
#else
    port_conf->rxmode.max_rx_pkt_len = mtu;
    if (mtu > RTE_ETHER_MAX_LEN) {
        port_conf->rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
    }
#endif
}

static void PortConfSetInterruptMode(const DPDKIfaceConfig *iconf, struct rte_eth_conf *port_conf)
{
    SCLogConfig("%s: interrupt mode is %s", iconf->iface,
            iconf->flags & DPDK_IRQ_MODE ? "enabled" : "disabled");
    if (iconf->flags & DPDK_IRQ_MODE)
        port_conf->intr_conf.rxq = 1;
}

static void PortConfSetRSSConf(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
    if (dev_info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_RSS_HASH) {
        if (iconf->nb_rx_queues > 1) {
            SCLogConfig("%s: RSS enabled for %d queues", iconf->iface, iconf->nb_rx_queues);
            port_conf->rx_adv_conf.rss_conf = (struct rte_eth_rss_conf){
                .rss_key = RSS_HKEY,
                .rss_key_len = RSS_HKEY_LEN,
                .rss_hf = iconf->rss_hf,
            };

            const char *dev_driver = dev_info->driver_name;
            if (strcmp(dev_info->driver_name, "net_bonding") == 0) {
                dev_driver = BondingDeviceDriverGet(iconf->port_id);
            }

            DeviceSetPMDSpecificRSS(&port_conf->rx_adv_conf.rss_conf, dev_driver);

            uint64_t rss_hf_tmp =
                    port_conf->rx_adv_conf.rss_conf.rss_hf & dev_info->flow_type_rss_offloads;
            if (port_conf->rx_adv_conf.rss_conf.rss_hf != rss_hf_tmp) {
                DumpRSSFlags(port_conf->rx_adv_conf.rss_conf.rss_hf, rss_hf_tmp);

                SCLogWarning("%s: modified RSS hash function based on hardware support: "
                             "requested:%#" PRIx64 ", configured:%#" PRIx64,
                        iconf->iface, port_conf->rx_adv_conf.rss_conf.rss_hf, rss_hf_tmp);
                port_conf->rx_adv_conf.rss_conf.rss_hf = rss_hf_tmp;
            }
            port_conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        } else {
            SCLogConfig("%s: RSS not enabled", iconf->iface);
            port_conf->rx_adv_conf.rss_conf.rss_key = NULL;
            port_conf->rx_adv_conf.rss_conf.rss_hf = 0;
        }
    } else {
        SCLogConfig("%s: RSS not supported", iconf->iface);
    }
}

static void PortConfSetChsumOffload(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
    if (iconf->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        SCLogConfig("%s: checksum validation disabled", iconf->iface);
    } else if ((dev_info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) ==
               RTE_ETH_RX_OFFLOAD_CHECKSUM) { // multibit comparison to make sure all bits are set
        if (iconf->checksum_mode == CHECKSUM_VALIDATION_ENABLE &&
                iconf->flags & DPDK_RX_CHECKSUM_OFFLOAD) {
            SCLogConfig("%s: IP, TCP and UDP checksum validation offloaded", iconf->iface);
            port_conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
        } else if (iconf->checksum_mode == CHECKSUM_VALIDATION_ENABLE &&
                   !(iconf->flags & DPDK_RX_CHECKSUM_OFFLOAD)) {
            SCLogConfig("%s: checksum validation enabled (but can be offloaded)", iconf->iface);
        }
    }
}

static void PortConfSetVlanOffload(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
    if (iconf->vlan_strip_enabled) {
        if (dev_info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) {
            port_conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
            SCLogConfig("%s: hardware VLAN stripping enabled", iconf->iface);
        } else {
            SCLogWarning("%s: hardware VLAN stripping enabled but not supported, disabling",
                    iconf->iface);
        }
    }
}

static void DeviceInitPortConf(const DPDKIfaceConfig *iconf,
        const struct rte_eth_dev_info *dev_info, struct rte_eth_conf *port_conf)
{
    DumpRXOffloadCapabilities(dev_info->rx_offload_capa);
    *port_conf = (struct rte_eth_conf){
            .rxmode = {
                    .mq_mode = RTE_ETH_MQ_RX_NONE,
                    .offloads = 0, // turn every offload off to prevent any packet modification
            },
            .txmode = {
                    .mq_mode = RTE_ETH_MQ_TX_NONE,
                    .offloads = 0,
            },
    };

    PortConfSetInterruptMode(iconf, port_conf);

    // configure RX offloads
    PortConfSetRSSConf(iconf, dev_info, port_conf);
    PortConfSetChsumOffload(iconf, dev_info, port_conf);
    DeviceSetMTU(port_conf, iconf->mtu);
    PortConfSetVlanOffload(iconf, dev_info, port_conf);

    if (dev_info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
}

static int DeviceConfigureQueues(DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info,
        const struct rte_eth_conf *port_conf)
{
    SCEnter();
    int retval;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;

    retval = DPDKDeviceResourcesInit(&(iconf->pkt_mempools), iconf->nb_rx_queues);
    if (retval < 0) {
        goto cleanup;
    }

    // +4 for VLAN header
    uint16_t mtu_size = iconf->mtu + RTE_ETHER_CRC_LEN + RTE_ETHER_HDR_LEN + 4;
    uint16_t mbuf_size = ROUNDUP(mtu_size, 1024) + RTE_PKTMBUF_HEADROOM;
    // ceil the div so e.g. mp_size of 262144 and 262143 both lead to 65535 on 4 rx queues
    uint32_t q_mp_sz = (iconf->mempool_size + iconf->nb_rx_queues - 1) / iconf->nb_rx_queues - 1;
    uint32_t q_mp_cache_sz = MempoolCacheSizeCalculate(q_mp_sz);
    SCLogInfo("%s: creating %u packet mempools of size %u, cache size %u, mbuf size %u",
            iconf->iface, iconf->nb_rx_queues, q_mp_sz, q_mp_cache_sz, mbuf_size);
    for (int i = 0; i < iconf->nb_rx_queues; i++) {
        char mempool_name[64];
        snprintf(mempool_name, sizeof(mempool_name), "mp_%d_%.20s", i, iconf->iface);
        iconf->pkt_mempools->pkt_mp[i] = rte_pktmbuf_pool_create(
                mempool_name, q_mp_sz, q_mp_cache_sz, 0, mbuf_size, (int)iconf->socket_id);
        if (iconf->pkt_mempools->pkt_mp[i] == NULL) {
            retval = -rte_errno;
            SCLogError("%s: rte_pktmbuf_pool_create failed with code %d (mempool: %s) - %s",
                    iconf->iface, rte_errno, mempool_name, rte_strerror(rte_errno));
            goto cleanup;
        }
    }

    for (uint16_t queue_id = 0; queue_id < iconf->nb_rx_queues; queue_id++) {
        rxq_conf = dev_info->default_rxconf;
        rxq_conf.offloads = port_conf->rxmode.offloads;
        rxq_conf.rx_thresh.hthresh = 0;
        rxq_conf.rx_thresh.pthresh = 0;
        rxq_conf.rx_thresh.wthresh = 0;
        rxq_conf.rx_free_thresh = 0;
        rxq_conf.rx_drop_en = 0;
        SCLogConfig("%s: setting up RX queue %d: rx_desc: %u offloads: 0x%" PRIx64
                    " hthresh: %" PRIu8 " pthresh: %" PRIu8 " wthresh: %" PRIu8
                    " free_thresh: %" PRIu16 " drop_en: %" PRIu8,
                iconf->iface, queue_id, iconf->nb_rx_desc, rxq_conf.offloads,
                rxq_conf.rx_thresh.hthresh, rxq_conf.rx_thresh.pthresh, rxq_conf.rx_thresh.wthresh,
                rxq_conf.rx_free_thresh, rxq_conf.rx_drop_en);

        retval = rte_eth_rx_queue_setup(iconf->port_id, queue_id, iconf->nb_rx_desc,
                (unsigned int)iconf->socket_id, &rxq_conf, iconf->pkt_mempools->pkt_mp[queue_id]);
        if (retval < 0) {
            SCLogError("%s: failed to setup RX queue %u: %s", iconf->iface, queue_id,
                    rte_strerror(-retval));
            goto cleanup;
        }
    }

    for (uint16_t queue_id = 0; queue_id < iconf->nb_tx_queues; queue_id++) {
        txq_conf = dev_info->default_txconf;
        txq_conf.offloads = port_conf->txmode.offloads;
        SCLogConfig("%s: setting up TX queue %d: tx_desc: %" PRIu16 " tx: offloads: 0x%" PRIx64
                    " hthresh: %" PRIu8 " pthresh: %" PRIu8 " wthresh: %" PRIu8
                    " tx_free_thresh: %" PRIu16 " tx_rs_thresh: %" PRIu16
                    " txq_deferred_start: %" PRIu8,
                iconf->iface, queue_id, iconf->nb_tx_desc, txq_conf.offloads,
                txq_conf.tx_thresh.hthresh, txq_conf.tx_thresh.pthresh, txq_conf.tx_thresh.wthresh,
                txq_conf.tx_free_thresh, txq_conf.tx_rs_thresh, txq_conf.tx_deferred_start);
        retval = rte_eth_tx_queue_setup(iconf->port_id, queue_id, iconf->nb_tx_desc,
                (unsigned int)iconf->socket_id, &txq_conf);
        if (retval < 0) {
            SCLogError("%s: failed to setup TX queue %u: %s", iconf->iface, queue_id,
                    rte_strerror(-retval));
            retval = -1; // the error code explained, informing about failure
            goto cleanup;
        }
    }

    SCReturnInt(0);

cleanup:
    DPDKDeviceResourcesDeinit(&iconf->pkt_mempools);
    SCReturnInt(retval);
}

static int DeviceValidateOutIfaceConfig(DPDKIfaceConfig *iconf)
{
    SCEnter();
    int retval;
    DPDKIfaceConfig *out_iconf = NULL;
    ConfigInit(&out_iconf);
    if (out_iconf == NULL) {
        FatalError("Copy interface of the interface \"%s\" is NULL", iconf->iface);
    }

    retval = ConfigLoad(out_iconf, iconf->out_iface);
    if (retval < 0) {
        SCLogError("%s: fail to load config of interface", iconf->out_iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    }

    if (iconf->nb_rx_queues != out_iconf->nb_tx_queues) {
        // the other direction is validated when the copy interface is configured
        SCLogError("%s: configured %d RX queues but copy interface %s has %d TX queues"
                   " - number of queues must be equal",
                iconf->iface, iconf->nb_rx_queues, out_iconf->iface, out_iconf->nb_tx_queues);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    } else if (iconf->mtu != out_iconf->mtu) {
        SCLogError("%s: configured MTU of %d but copy interface %s has MTU set to %d"
                   " - MTU must be equal",
                iconf->iface, iconf->mtu, out_iconf->iface, out_iconf->mtu);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    } else if (iconf->copy_mode != out_iconf->copy_mode) {
        SCLogError("%s: copy modes of interfaces %s and %s are not equal", iconf->iface,
                iconf->iface, out_iconf->iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    } else if (strcmp(iconf->iface, out_iconf->out_iface) != 0) {
        // check if the other iface has the current iface set as a copy iface
        SCLogError("%s: copy interface of %s is not set to %s", iconf->iface, out_iconf->iface,
                iconf->iface);
        out_iconf->DerefFunc(out_iconf);
        SCReturnInt(-EINVAL);
    }

    out_iconf->DerefFunc(out_iconf);
    SCReturnInt(0);
}

static int DeviceConfigureIPS(DPDKIfaceConfig *iconf)
{
    SCEnter();
    if (iconf->out_iface != NULL) {
        if (!rte_eth_dev_is_valid_port(iconf->out_port_id)) {
            SCLogError("%s: retrieved copy interface port ID \"%d\" is invalid or the device is "
                       "not attached ",
                    iconf->iface, iconf->out_port_id);
            SCReturnInt(-ENODEV);
        }
        int32_t out_port_socket_id;
        int retval = DPDKDeviceSetSocketID(iconf->out_port_id, &out_port_socket_id);
        if (retval < 0) {
            SCLogError("%s: invalid socket id: %s", iconf->out_iface, rte_strerror(-retval));
            SCReturnInt(retval);
        }

        if (iconf->socket_id != out_port_socket_id) {
            SCLogWarning(
                    "%s: out iface %s is not on the same NUMA node (%s - NUMA %d, %s - NUMA %d)",
                    iconf->iface, iconf->out_iface, iconf->iface, iconf->socket_id,
                    iconf->out_iface, out_port_socket_id);
        }

        retval = DeviceValidateOutIfaceConfig(iconf);
        if (retval != 0) {
            // Error will be written out by the validation function
            SCReturnInt(retval);
        }

        if (iconf->copy_mode == DPDK_COPY_MODE_IPS)
            SCLogInfo("%s: DPDK IPS mode activated: %s->%s", iconf->iface, iconf->iface,
                    iconf->out_iface);
        else if (iconf->copy_mode == DPDK_COPY_MODE_TAP)
            SCLogInfo("%s: DPDK TAP mode activated: %s->%s", iconf->iface, iconf->iface,
                    iconf->out_iface);
    }
    SCReturnInt(0);
}

/**
 * Function verifies changes in e.g. device info after configuration has
 * happened. Sometimes (e.g. DPDK Bond PMD with Intel NICs i40e/ixgbe) change
 * device info only after the device configuration.
 * @param iconf
 * @param dev_info
 * @return 0 on success, -EAGAIN when reconfiguration is needed, <0 on failure
 */
static int32_t DeviceVerifyPostConfigure(
        const DPDKIfaceConfig *iconf, const struct rte_eth_dev_info *dev_info)
{
    SCEnter();
    struct rte_eth_dev_info post_conf_dev_info = { 0 };
    int32_t ret = rte_eth_dev_info_get(iconf->port_id, &post_conf_dev_info);
    if (ret < 0) {
        SCLogError("%s: getting device info failed: %s", iconf->iface, rte_strerror(-ret));
        SCReturnInt(ret);
    }

    if (dev_info->flow_type_rss_offloads != post_conf_dev_info.flow_type_rss_offloads ||
            dev_info->rx_offload_capa != post_conf_dev_info.rx_offload_capa ||
            dev_info->tx_offload_capa != post_conf_dev_info.tx_offload_capa ||
            dev_info->max_rx_queues != post_conf_dev_info.max_rx_queues ||
            dev_info->max_tx_queues != post_conf_dev_info.max_tx_queues ||
            dev_info->max_mtu != post_conf_dev_info.max_mtu) {
        SCLogWarning("%s: device information severely changed after configuration, reconfiguring",
                iconf->iface);
        return -EAGAIN;
    }

    if (strcmp(dev_info->driver_name, "net_bonding") == 0) {
        ret = BondingAllDevicesSameDriver(iconf->port_id);
        if (ret < 0) {
            SCLogError("%s: bond port uses port with different DPDK drivers", iconf->iface);
            SCReturnInt(ret);
        }
    }

    return 0;
}

static int DeviceConfigure(DPDKIfaceConfig *iconf)
{
    SCEnter();
    if (!rte_eth_dev_is_valid_port(iconf->port_id)) {
        SCLogError("%s: retrieved port ID \"%d\" is invalid or the device is not attached ",
                iconf->iface, iconf->port_id);
        SCReturnInt(-ENODEV);
    }

    int32_t retval = DPDKDeviceSetSocketID(iconf->port_id, &iconf->socket_id);
    if (retval < 0) {
        SCLogError("%s: invalid socket id: %s", iconf->iface, rte_strerror(-retval));
        SCReturnInt(retval);
    }

    struct rte_eth_dev_info dev_info = { 0 };
    retval = rte_eth_dev_info_get(iconf->port_id, &dev_info);
    if (retval < 0) {
        SCLogError("%s: getting device info failed: %s", iconf->iface, rte_strerror(-retval));
        SCReturnInt(retval);
    }

    if (iconf->nb_rx_queues > dev_info.max_rx_queues) {
        SCLogError("%s: configured RX queues %u is higher than device maximum (%" PRIu16 ")",
                iconf->iface, iconf->nb_rx_queues, dev_info.max_rx_queues);
        SCReturnInt(-ERANGE);
    }

    if (iconf->nb_tx_queues > dev_info.max_tx_queues) {
        SCLogError("%s: configured TX queues %u is higher than device maximum (%" PRIu16 ")",
                iconf->iface, iconf->nb_tx_queues, dev_info.max_tx_queues);
        SCReturnInt(-ERANGE);
    }

    retval = DeviceValidateMTU(iconf, &dev_info);
    if (retval < 0)
        return retval;

    struct rte_eth_conf port_conf = { 0 };
    DeviceInitPortConf(iconf, &dev_info, &port_conf);
    if (port_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
        // Suricata does not need recalc checksums now
        iconf->checksum_mode = CHECKSUM_VALIDATION_OFFLOAD;
    }

    retval = rte_eth_dev_configure(
            iconf->port_id, iconf->nb_rx_queues, iconf->nb_tx_queues, &port_conf);
    if (retval < 0) {
        SCLogError("%s: failed to configure the device: %s", iconf->iface, rte_strerror(-retval));
        SCReturnInt(retval);
    }

    retval = DeviceVerifyPostConfigure(iconf, &dev_info);
    if (retval < 0)
        return retval;

    uint16_t tmp_nb_rx_desc = iconf->nb_rx_desc;
    uint16_t tmp_nb_tx_desc = iconf->nb_tx_desc;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(
            iconf->port_id, &iconf->nb_rx_desc, &iconf->nb_tx_desc);
    if (retval != 0) {
        SCLogError("%s: failed to adjust device queue descriptors: %s", iconf->iface,
                rte_strerror(-retval));
        SCReturnInt(retval);
    } else if (tmp_nb_rx_desc != iconf->nb_rx_desc || tmp_nb_tx_desc != iconf->nb_tx_desc) {
        SCLogWarning("%s: device queue descriptors adjusted (RX: from %u to %u, TX: from %u to %u)",
                iconf->iface, tmp_nb_rx_desc, iconf->nb_rx_desc, tmp_nb_tx_desc, iconf->nb_tx_desc);
    }

    retval = iconf->flags & DPDK_MULTICAST ? rte_eth_allmulticast_enable(iconf->port_id)
                                           : rte_eth_allmulticast_disable(iconf->port_id);
    if (retval == -ENOTSUP) {
        retval = rte_eth_allmulticast_get(iconf->port_id);
        // when multicast is enabled but set to disable or vice versa
        if ((retval == 1 && !(iconf->flags & DPDK_MULTICAST)) ||
                (retval == 0 && (iconf->flags & DPDK_MULTICAST))) {
            SCLogWarning("%s: cannot configure allmulticast, the port is %sin allmulticast mode",
                    iconf->iface, retval == 1 ? "" : "not ");
        } else if (retval < 0) {
            SCLogError("%s: failed to get multicast mode: %s", iconf->iface, rte_strerror(-retval));
            SCReturnInt(retval);
        }
    } else if (retval < 0) {
        SCLogError("%s: error when changing multicast setting: %s", iconf->iface,
                rte_strerror(-retval));
        SCReturnInt(retval);
    }

    retval = iconf->flags & DPDK_PROMISC ? rte_eth_promiscuous_enable(iconf->port_id)
                                         : rte_eth_promiscuous_disable(iconf->port_id);
    if (retval == -ENOTSUP) {
        retval = rte_eth_promiscuous_get(iconf->port_id);
        if ((retval == 1 && !(iconf->flags & DPDK_PROMISC)) ||
                (retval == 0 && (iconf->flags & DPDK_PROMISC))) {
            SCLogError("%s: cannot configure promiscuous mode, the port is in %spromiscuous mode",
                    iconf->iface, retval == 1 ? "" : "non-");
            SCReturnInt(TM_ECODE_FAILED);
        } else if (retval < 0) {
            SCLogError(
                    "%s: failed to get promiscuous mode: %s", iconf->iface, rte_strerror(-retval));
            SCReturnInt(retval);
        }
    } else if (retval < 0) {
        SCLogError("%s: error when changing promiscuous setting: %s", iconf->iface,
                rte_strerror(-retval));
        SCReturnInt(TM_ECODE_FAILED);
    }

    // set maximum transmission unit
    SCLogConfig("%s: setting MTU to %d", iconf->iface, iconf->mtu);
    retval = rte_eth_dev_set_mtu(iconf->port_id, iconf->mtu);
    if (retval == -ENOTSUP) {
        // if it is not possible to set the MTU, retrieve it
        retval = rte_eth_dev_get_mtu(iconf->port_id, &iconf->mtu);
        if (retval < 0) {
            SCLogError("%s: failed to retrieve MTU: %s", iconf->iface, rte_strerror(-retval));
            SCReturnInt(retval);
        }
        SCLogWarning(
                "%s: changing MTU is not supported, current MTU: %u", iconf->iface, iconf->mtu);
    } else if (retval < 0) {
        SCLogError(
                "%s: failed to set MTU to %u: %s", iconf->iface, iconf->mtu, rte_strerror(-retval));
        SCReturnInt(retval);
    }

    retval = DeviceConfigureQueues(iconf, &dev_info, &port_conf);
    if (retval < 0) {
        SCReturnInt(retval);
    }

    retval = DeviceConfigureIPS(iconf);
    if (retval < 0) {
        SCReturnInt(retval);
    }

    SCReturnInt(0);
}

static void *ParseDpdkConfigAndConfigureDevice(const char *iface)
{
    int retval;
    DPDKIfaceConfig *iconf = ConfigParse(iface);
    if (iconf == NULL) {
        FatalError("DPDK configuration could not be parsed");
    }

    retval = DeviceConfigure(iconf);
    if (retval == -EAGAIN) {
        // for e.g. bonding PMD it needs to be reconfigured
        retval = DeviceConfigure(iconf);
    }

    if (retval < 0) { // handles both configure attempts
        iconf->DerefFunc(iconf);
        if (rte_eal_cleanup() != 0)
            FatalError("EAL cleanup failed: %s", rte_strerror(-retval));

        if (retval == -ENOMEM) {
            FatalError("%s: memory allocation failed - consider"
                       "%s freeing up some memory.",
                    iface,
                    rte_eal_has_hugepages() != 0 ? " increasing the number of hugepages or" : "");
        } else {
            FatalError("%s: failed to configure", iface);
        }
    }

    SC_ATOMIC_RESET(iconf->ref);
    (void)SC_ATOMIC_ADD(iconf->ref, iconf->threads);
    // This counter is increased by worker threads that individually pick queue IDs.
    SC_ATOMIC_RESET(iconf->queue_id);
    SC_ATOMIC_RESET(iconf->inconsistent_numa_cnt);
    iconf->workers_sync = SCCalloc(1, sizeof(*iconf->workers_sync));
    if (iconf->workers_sync == NULL) {
        FatalError("Failed to allocate memory for workers_sync");
    }
    SC_ATOMIC_RESET(iconf->workers_sync->worker_checked_in);
    iconf->workers_sync->worker_cnt = iconf->threads;

    // initialize LiveDev DPDK values
    LiveDevice *ldev_instance = LiveGetDevice(iface);
    if (ldev_instance == NULL) {
        FatalError("Device %s is not registered as a live device", iface);
    }
    for (uint16_t i = 0; i < iconf->threads; i++) {
        ldev_instance->dpdk_vars = iconf->pkt_mempools;
        iconf->pkt_mempools = NULL;
    }
    return iconf;
}

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to or copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * After configuration is loaded, DPDK also configures the device according to the settings.
 *
 * \return a DPDKIfaceConfig corresponding to the interface name
 */

static int DPDKConfigGetThreadsCount(void *conf)
{
    if (conf == NULL)
        FatalError("Configuration file is NULL");

    DPDKIfaceConfig *dpdk_conf = (DPDKIfaceConfig *)conf;
    return dpdk_conf->threads;
}

#endif /* HAVE_DPDK */

static int DPDKRunModeIsIPS(void)
{
    /* Find initial node */
    const char dpdk_node_query[] = "dpdk.interfaces";
    SCConfNode *dpdk_node = SCConfGetNode(dpdk_node_query);
    if (dpdk_node == NULL) {
        FatalError("Unable to get %s configuration node", dpdk_node_query);
    }

    const char default_iface[] = "default";
    SCConfNode *if_default = SCConfNodeLookupKeyValue(dpdk_node, "interface", default_iface);
    int nlive = LiveGetDeviceCount();
    bool has_ips = false;
    bool has_ids = false;
    for (int ldev = 0; ldev < nlive; ldev++) {
        const char *live_dev = LiveGetDeviceName(ldev);
        if (live_dev == NULL)
            FatalError("Unable to get device id %d from LiveDevice list", ldev);

        SCConfNode *if_root = ConfFindDeviceConfig(dpdk_node, live_dev);
        if (if_root == NULL) {
            if (if_default == NULL)
                FatalError("Unable to get %s or %s  interface", live_dev, default_iface);

            if_root = if_default;
        }

        const char *copymodestr = NULL;
        const char *copyifacestr = NULL;
        if (SCConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1 &&
                SCConfGetChildValue(if_root, "copy-iface", &copyifacestr) == 1) {
            if (strcmp(copymodestr, "ips") == 0) {
                has_ips = true;
            } else {
                has_ids = true;
            }
        } else {
            has_ids = true;
        }

        if (has_ids && has_ips) {
            FatalError("Copy-mode of interface %s mixes with the previously set copy-modes "
                       "(only IDS/TAP and IPS copy-mode combinations are allowed in DPDK",
                    live_dev);
        }
    }

    return has_ips;
}

static int DPDKRunModeEnableIPS(void)
{
    int r = DPDKRunModeIsIPS();
    if (r == 1) {
        SCLogInfo("Setting IPS mode");
        EngineModeSetIPS();
    }
    return r;
}

const char *RunModeDpdkGetDefaultMode(void)
{
    return "workers";
}

void RunModeDpdkRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "workers",
            "Workers DPDK mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeIdsDpdkWorkers, DPDKRunModeEnableIPS);
}

/**
 * \brief Workers version of the DPDK processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsDpdkWorkers(void)
{
    SCEnter();
#ifdef HAVE_DPDK
    int ret;

    TimeModeSetLive();

    InitEal();
    ret = RunModeSetLiveCaptureWorkers(ParseDpdkConfigAndConfigureDevice, DPDKConfigGetThreadsCount,
            "ReceiveDPDK", "DecodeDPDK", thread_name_workers, NULL);
    if (ret != 0) {
        FatalError("Unable to start runmode");
    }

    SCLogDebug("RunModeIdsDpdkWorkers initialised");

#endif /* HAVE_DPDK */
    SCReturnInt(0);
}

/**
 * @}
 */
