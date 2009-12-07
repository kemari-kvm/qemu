#ifndef __DEVICE_TAP_H__
#define __DEVICE_TAP_H__

#include "qemu-queue.h"
#include "ioport.h"
#include "monitor.h"

typedef struct device_tap DTap ;

struct device_tap_entry {
    const char *name;
    int type;
    void *opaque;
    int (*register_tap)(DTap *dtap, void *opaque);
    int (*unregister_tap)(DTap *dtap, void *opaque);
    int (*optimize_tap)(int mode); /* maybe unnecessary */

    QLIST_ENTRY(device_tap_entry) entries;
};

enum  {
    DTAP_STATUS_OFF         = 0,
    DTAP_STATUS_CREATED     = 1,
    DTAP_STATUS_INITIALIZED = 2
};

struct device_tap {
    int status;
    int tap_ioport_read[MAX_IOPORTS][3];
    int tap_ioport_write[MAX_IOPORTS][3];
/*     int tap_iomem_read[IO_MEM_NB_ENTRIES][4]; */
/*     int tap_iomem_write[IO_MEM_NB_ENTRIES][4]; */
    void (*tap_func)(void *opaque);

    QLIST_HEAD(dtap_head, device_tap_entry) dtap_head;
};

void dtap_func(void *opaque);

int dtap_init(void);
int tap_dev_init(const char *name, void *opaque,
                 int (*register_tap)(DTap *dtap, void *opaque),
                 int (*unregister_tap)(DTap *dtap, void *opaque));
int tap_dev_exit(void *opaque);
int register_tap_all(void (*func)(void *opaque));
int unregister_tap_all(void);

/* Temporary place here for debug */
void do_device_tap(Monitor *mon, const QDict *qdict);
#endif

