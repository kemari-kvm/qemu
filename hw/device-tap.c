#include <string.h>
#include <stdio.h>

#include "hw/device-tap.h"
#include "monitor.h"
#include "qemu-common.h"
#include "qemu-queue.h"
#include "qdev.h"

#define DEBUG_DEVICE_TAP

#ifdef DEBUG_DEVICE_TAP
#define dprintf(fmt, ...)						\
    do { printf("device-tap: " fmt, ## __VA_ARGS__); } while (0)
#else
#define dprintf(fmt, ...)			\
    do { } while (0)
#endif

#define DTAP_NET (1 << 2)
#define DTAP_BLK (1 << 3)


static const char *dtap_net_white_list[] = {"virtio-net-pci", NULL}; 
static const char *dtap_blk_white_list[] = {"virtio-blk-pci", NULL}; 

static DTap dtap;

static void 
dtap_alloc_entry(const char *name, void *opaque, int type,
                 int (*register_tap)(DTap *dtap, void *opaque),
                 int (*unregister_tap)(DTap *dtap, void *opaque))
{
    struct device_tap_entry *dtap_entry;

    dtap_entry = qemu_mallocz(sizeof(struct device_tap_entry));
    if (dtap_entry == NULL) {
        fprintf(stderr, "%s %d: Out of memory\n", __func__, __LINE__);
        exit(1);
    }

    dtap_entry->name = name;
    dtap_entry->type = type;
    dtap_entry->opaque = opaque;
    dtap_entry->register_tap = register_tap;
    dtap_entry->unregister_tap = unregister_tap;

    QLIST_INSERT_HEAD(&dtap.dtap_head, dtap_entry, entries);
}

static void dtap_free_entry(struct device_tap_entry *dtap_entry)
{
    QLIST_REMOVE(dtap_entry, entries);
    qemu_free(dtap_entry);
}

void dtap_func(void *opaque)
{
    if (likely(dtap.tap_func))
        dtap.tap_func(opaque);
}

int dtap_init(void)
{
    QLIST_INIT(&dtap.dtap_head);
    dtap.status = DTAP_STATUS_INITIALIZED;
    return 0;
}

int tap_dev_init(const char *name, void *opaque,
                 int (*register_tap)(DTap *dtap, void *opaque),
                 int (*unregister_tap)(DTap *dtap, void *opaque))
{
    int i;

    if (dtap.status == DTAP_STATUS_OFF)
        dtap_init();

    for (i = 0; dtap_net_white_list[i] != NULL ||
             dtap_blk_white_list[i] != NULL; i++) {
        if (dtap_net_white_list[i] != NULL &&
            !strcmp(dtap_net_white_list[i], name)) {
            dtap_alloc_entry(name, opaque, DTAP_NET,
                             register_tap, unregister_tap);
        }
        if (dtap_blk_white_list[i] != NULL &&
            !strcmp(dtap_blk_white_list[i], name)) {
            dtap_alloc_entry(name, opaque, DTAP_BLK,
                             register_tap, unregister_tap);
        }
    }

    return 0;
}

int tap_dev_exit(void *opaque)
{
    struct device_tap_entry *dtap_entry;

    QLIST_FOREACH(dtap_entry, &dtap.dtap_head, entries) {
        if (dtap_entry->opaque == opaque) {
            dtap_entry->unregister_tap(&dtap, dtap_entry->opaque);
            dtap_free_entry(dtap_entry);
        }
    }

    return !QLIST_EMPTY(&dtap.dtap_head);
}

int register_tap_all(int (*func)(void *opaque))
{
    struct device_tap_entry *dtap_entry;
    DeviceInfo *info;

    if (func == NULL)
        return -1;

    if (device_info_list == NULL)
        return -1;

    for (info = device_info_list; info != NULL; info = info->next)
        dprintf("name \"%s\", bus %s\n", info->name, info->bus_info->name);

    for (info = device_info_list; info != NULL; info = info->next) {
        QLIST_FOREACH(dtap_entry, &dtap.dtap_head, entries) {
            if (!strcmp(info->name, dtap_entry->name)) {
                dtap.tap_func = dtap.tap_func ? : func;
                dtap_entry->register_tap(&dtap, dtap_entry->opaque);
                dtap.status |= dtap_entry->type;
            }
        }
    }

    if (!(dtap.status && DTAP_NET) || !(dtap.status && DTAP_BLK))
        return -1;

    return 0;
}

int unregister_tap_all(void)
{
    struct device_tap_entry *dtap_entry;
    DeviceInfo *info;

    if (dtap.status == DTAP_STATUS_OFF)
        return -1;

    if (device_info_list == NULL)
        return -1;

    for (info = device_info_list; info != NULL; info = info->next)
        dprintf("name \"%s\", bus %s\n", info->name, info->bus_info->name);

    for (info = device_info_list; info != NULL; info = info->next) {
        QLIST_FOREACH(dtap_entry, &dtap.dtap_head, entries) {
            if (!strcmp(info->name, dtap_entry->name)) {
                dtap_entry->unregister_tap(&dtap, dtap_entry->opaque);
                dtap.status = 1;
            }
        }
    }

    return 0;
}

static int print_opaque(void *opaque)
{
    DeviceInfo *qdev = opaque;
    dprintf("name %s\n", qdev->name);
    return 0;
}

void do_device_tap(Monitor *mon, const QDict *qdict)
{
    const char *status;

    status = qdict_get_str(qdict, "state");

    if (!strcmp(status, "on"))
        register_tap_all(print_opaque);
    else if (!strcmp(status, "off"))
        unregister_tap_all();
    else {
        monitor_printf(mon, "invalid status: %s\n", status);
    }
}
