/*
 * Event Tap functions for QEMU
 *
 * Copyright (c) 2010 Nippon Telegraph and Telephone Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu-common.h"
#include "qemu-error.h"
#include "block.h"
#include "block_int.h"
#include "ioport.h"
#include "osdep.h"
#include "sysemu.h"
#include "hw/hw.h"
#include "net.h"
#include "event-tap.h"
#include "trace.h"

enum EVENT_TAP_STATE {
    EVENT_TAP_OFF,
    EVENT_TAP_ON,
    EVENT_TAP_SUSPEND,
    EVENT_TAP_FLUSH,
    EVENT_TAP_LOAD,
    EVENT_TAP_REPLAY,
};

static enum EVENT_TAP_STATE event_tap_state = EVENT_TAP_OFF;

typedef struct EventTapIOport {
    uint32_t address;
    uint32_t data;
    int      index;
} EventTapIOport;

#define MMIO_BUF_SIZE 8

typedef struct EventTapMMIO {
    uint64_t address;
    uint8_t  buf[MMIO_BUF_SIZE];
    int      len;
} EventTapMMIO;

typedef struct EventTapNetReq {
    char *device_name;
    int iovcnt;
    int vlan_id;
    bool vlan_needed;
    bool async;
    struct iovec *iov;
    NetPacketSent *sent_cb;
} EventTapNetReq;

#define MAX_BLOCK_REQUEST 32

typedef struct EventTapAIOCB EventTapAIOCB;

typedef struct EventTapBlkReq {
    char *device_name;
    int num_reqs;
    int num_cbs;
    bool is_flush;
    BlockRequest reqs[MAX_BLOCK_REQUEST];
    EventTapAIOCB *acb[MAX_BLOCK_REQUEST];
} EventTapBlkReq;

#define EVENT_TAP_IOPORT (1 << 0)
#define EVENT_TAP_MMIO   (1 << 1)
#define EVENT_TAP_NET    (1 << 2)
#define EVENT_TAP_BLK    (1 << 3)

#define EVENT_TAP_TYPE_MASK (EVENT_TAP_NET - 1)

typedef struct EventTapLog {
    int mode;
    union {
        EventTapIOport ioport;
        EventTapMMIO mmio;
    };
    union {
        EventTapNetReq net_req;
        EventTapBlkReq blk_req;
    };
    QTAILQ_ENTRY(EventTapLog) node;
} EventTapLog;

struct EventTapAIOCB {
    BlockDriverAIOCB common;
    BlockDriverAIOCB *acb;
    bool is_canceled;
};

static EventTapLog *last_event_tap;

static QTAILQ_HEAD(, EventTapLog) event_list;
static QTAILQ_HEAD(, EventTapLog) event_pool;

static int (*event_tap_cb)(void);
static QEMUBH *event_tap_bh;
static VMChangeStateEntry *vmstate;

static void event_tap_bh_cb(void *p)
{
    if (event_tap_cb) {
        event_tap_cb();
    }

    qemu_bh_delete(event_tap_bh);
    event_tap_bh = NULL;
}

static void event_tap_schedule_bh(void)
{
    trace_event_tap_ignore_bh(!!event_tap_bh);

    /* if bh is already set, we ignore it for now */
    if (event_tap_bh) {
        return;
    }

    event_tap_bh = qemu_bh_new(event_tap_bh_cb, NULL);
    qemu_bh_schedule(event_tap_bh);

    return;
}

static void *event_tap_alloc_log(void)
{
    EventTapLog *log;

    if (QTAILQ_EMPTY(&event_pool)) {
        log = qemu_mallocz(sizeof(EventTapLog));
    } else {
        log = QTAILQ_FIRST(&event_pool);
        QTAILQ_REMOVE(&event_pool, log, node);
    }

    return log;
}

static void event_tap_free_net_req(EventTapNetReq *net_req);
static void event_tap_free_blk_req(EventTapBlkReq *blk_req);

static void event_tap_free_log(EventTapLog *log)
{
    int mode = log->mode & ~EVENT_TAP_TYPE_MASK;

    if (mode == EVENT_TAP_NET) {
        event_tap_free_net_req(&log->net_req);
    } else if (mode == EVENT_TAP_BLK) {
        event_tap_free_blk_req(&log->blk_req);
    }

    log->mode = 0;

    /* return the log to event_pool */
    QTAILQ_INSERT_HEAD(&event_pool, log, node);
}

static void event_tap_free_pool(void)
{
    EventTapLog *log, *next;

    QTAILQ_FOREACH_SAFE(log, &event_pool, node, next) {
        QTAILQ_REMOVE(&event_pool, log, node);
        qemu_free(log);
    }
}

static void event_tap_free_net_req(EventTapNetReq *net_req)
{
    int i;

    if (!net_req->async) {
        for (i = 0; i < net_req->iovcnt; i++) {
            qemu_free(net_req->iov[i].iov_base);
        }
        qemu_free(net_req->iov);
    } else if (event_tap_state >= EVENT_TAP_LOAD) {
        qemu_free(net_req->iov);
    }

    qemu_free(net_req->device_name);
}

static void event_tap_alloc_net_req(EventTapNetReq *net_req,
                                   VLANClientState *vc,
                                   const struct iovec *iov, int iovcnt,
                                   NetPacketSent *sent_cb, bool async)
{
    int i;

    net_req->iovcnt = iovcnt;
    net_req->async = async;
    net_req->device_name = qemu_strdup(vc->name);
    net_req->sent_cb = sent_cb;

    if (vc->vlan) {
        net_req->vlan_needed = 1;
        net_req->vlan_id = vc->vlan->id;
    } else {
        net_req->vlan_needed = 0;
    }

    if (async) {
        net_req->iov = (struct iovec *)iov;
    } else {
        net_req->iov = qemu_malloc(sizeof(struct iovec) * iovcnt);
        for (i = 0; i < iovcnt; i++) {
            net_req->iov[i].iov_base = qemu_malloc(iov[i].iov_len);
            memcpy(net_req->iov[i].iov_base, iov[i].iov_base, iov[i].iov_len);
            net_req->iov[i].iov_len = iov[i].iov_len;
        }
    }
}

static void event_tap_packet(VLANClientState *vc, const struct iovec *iov,
                            int iovcnt, NetPacketSent *sent_cb, bool async)
{
    int empty;
    EventTapLog *log = last_event_tap;

    if (!log) {
        trace_event_tap_no_event();
        log = event_tap_alloc_log();
    }

    if (log->mode & ~EVENT_TAP_TYPE_MASK) {
        trace_event_tap_already_used(log->mode & ~EVENT_TAP_TYPE_MASK);
        return;
    }

    log->mode |= EVENT_TAP_NET;
    event_tap_alloc_net_req(&log->net_req, vc, iov, iovcnt, sent_cb, async);

    empty = QTAILQ_EMPTY(&event_list);
    QTAILQ_INSERT_TAIL(&event_list, log, node);
    last_event_tap = NULL;

    if (empty) {
        event_tap_schedule_bh();
    }
}

void event_tap_send_packet(VLANClientState *vc, const uint8_t *buf, int size)
{
    struct iovec iov;

    assert(event_tap_state == EVENT_TAP_ON);

    iov.iov_base = (uint8_t *)buf;
    iov.iov_len = size;
    event_tap_packet(vc, &iov, 1, NULL, 0);

    return;
}

ssize_t event_tap_sendv_packet_async(VLANClientState *vc,
                                     const struct iovec *iov,
                                     int iovcnt, NetPacketSent *sent_cb)
{
    assert(event_tap_state == EVENT_TAP_ON);
    event_tap_packet(vc, iov, iovcnt, sent_cb, 1);
    return 0;
}

static void event_tap_net_flush(EventTapNetReq *net_req)
{
    VLANClientState *vc;
    ssize_t len;

    if (net_req->vlan_needed) {
        vc = qemu_find_vlan_client_by_name(NULL, net_req->vlan_id,
                                           net_req->device_name);
    } else {
        vc = qemu_find_netdev(net_req->device_name);
    }

    if (net_req->async) {
        len = qemu_sendv_packet_async(vc, net_req->iov, net_req->iovcnt,
                                      net_req->sent_cb);
        if (len) {
            net_req->sent_cb(vc, len);
        } else {
            /* packets are queued in the net layer */
            trace_event_tap_append_packet();
        }
    } else {
        qemu_send_packet(vc, net_req->iov[0].iov_base,
                         net_req->iov[0].iov_len);
    }

    /* force flush to avoid request inversion */
    qemu_aio_flush();
}

static void event_tap_net_save(QEMUFile *f, EventTapNetReq *net_req)
{
    ram_addr_t page_addr;
    int i, len;

    len = strlen(net_req->device_name);
    qemu_put_byte(f, len);
    qemu_put_buffer(f, (uint8_t *)net_req->device_name, len);
    qemu_put_byte(f, net_req->vlan_id);
    qemu_put_byte(f, net_req->vlan_needed);
    qemu_put_byte(f, net_req->async);
    qemu_put_be32(f, net_req->iovcnt);

    for (i = 0; i < net_req->iovcnt; i++) {
        qemu_put_be64(f, net_req->iov[i].iov_len);
        if (net_req->async) {
            page_addr =
                qemu_ram_addr_from_host_nofail(net_req->iov[i].iov_base);
            qemu_put_be64(f, page_addr);
        } else {
            qemu_put_buffer(f, (uint8_t *)net_req->iov[i].iov_base,
                            net_req->iov[i].iov_len);
        }
    }
}

static void event_tap_net_load(QEMUFile *f, EventTapNetReq *net_req)
{
    ram_addr_t page_addr;
    int i, len;

    len = qemu_get_byte(f);
    net_req->device_name = qemu_malloc(len + 1);
    qemu_get_buffer(f, (uint8_t *)net_req->device_name, len);
    net_req->device_name[len] = '\0';
    net_req->vlan_id = qemu_get_byte(f);
    net_req->vlan_needed = qemu_get_byte(f);
    net_req->async = qemu_get_byte(f);
    net_req->iovcnt = qemu_get_be32(f);
    net_req->iov = qemu_malloc(sizeof(struct iovec) * net_req->iovcnt);

    for (i = 0; i < net_req->iovcnt; i++) {
        net_req->iov[i].iov_len = qemu_get_be64(f);
        if (net_req->async) {
            page_addr = qemu_get_be64(f);
            net_req->iov[i].iov_base = qemu_get_ram_ptr(page_addr);
        } else {
            net_req->iov[i].iov_base = qemu_malloc(net_req->iov[i].iov_len);
            qemu_get_buffer(f, (uint8_t *)net_req->iov[i].iov_base,
                            net_req->iov[i].iov_len);
        }
    }
}

static void event_tap_free_blk_req(EventTapBlkReq *blk_req)
{
    int i;

    if (event_tap_state >= EVENT_TAP_LOAD && !blk_req->is_flush) {
        for (i = 0; i < blk_req->num_reqs; i++) {
            qemu_iovec_destroy(blk_req->reqs[i].qiov);
            qemu_free(blk_req->reqs[i].qiov);
        }
    }

    qemu_free(blk_req->device_name);
}

static void event_tap_blk_cb(void *opaque, int ret)
{
    EventTapLog *log = container_of(opaque, EventTapLog, blk_req);
    EventTapBlkReq *blk_req = opaque;
    int i;

    blk_req->num_cbs--;

    /* all outstanding requests are flushed */
    if (blk_req->num_cbs == 0) {
        for (i = 0; i < blk_req->num_reqs; i++) {
            EventTapAIOCB *eacb = blk_req->acb[i];
            eacb->common.cb(eacb->common.opaque, ret);
            qemu_aio_release(eacb);
        }

        event_tap_free_log(log);
    }
}

static void event_tap_bdrv_aio_cancel(BlockDriverAIOCB *acb)
{
    EventTapAIOCB *eacb = container_of(acb, EventTapAIOCB, common);

    /* check if already passed to block layer */
    if (eacb->acb) {
        bdrv_aio_cancel(eacb->acb);
    } else {
        eacb->is_canceled = 1;
    }
}

static AIOPool event_tap_aio_pool = {
    .aiocb_size = sizeof(EventTapAIOCB),
    .cancel     = event_tap_bdrv_aio_cancel,
};

static void event_tap_alloc_blk_req(EventTapBlkReq *blk_req,
                                    BlockDriverState *bs, BlockRequest *reqs,
                                    int num_reqs, void *opaque, bool is_flush)
{
    int i;

    blk_req->num_reqs = num_reqs;
    blk_req->num_cbs = num_reqs;
    blk_req->device_name = qemu_strdup(bs->device_name);
    blk_req->is_flush = is_flush;

    for (i = 0; i < num_reqs; i++) {
        blk_req->reqs[i].sector = reqs[i].sector;
        blk_req->reqs[i].nb_sectors = reqs[i].nb_sectors;
        blk_req->reqs[i].qiov = reqs[i].qiov;
        blk_req->reqs[i].cb = event_tap_blk_cb;
        blk_req->reqs[i].opaque = opaque;

        blk_req->acb[i] = qemu_aio_get(&event_tap_aio_pool, bs,
                                       reqs[i].cb, reqs[i].opaque);
    }
}

static EventTapBlkReq *event_tap_bdrv(BlockDriverState *bs, BlockRequest *reqs,
                                      int num_reqs, bool is_flush)
{
    EventTapLog *log = last_event_tap;
    int empty;

    if (!log) {
        trace_event_tap_no_event();
        log = event_tap_alloc_log();
    }

    if (log->mode & ~EVENT_TAP_TYPE_MASK) {
        trace_event_tap_already_used(log->mode & ~EVENT_TAP_TYPE_MASK);
        return NULL;
    }

    log->mode |= EVENT_TAP_BLK;
    event_tap_alloc_blk_req(&log->blk_req, bs, reqs,
                            num_reqs, &log->blk_req, is_flush);

    empty = QTAILQ_EMPTY(&event_list);
    QTAILQ_INSERT_TAIL(&event_list, log, node);
    last_event_tap = NULL;

    if (empty) {
        event_tap_schedule_bh();
    }

    return &log->blk_req;
}

BlockDriverAIOCB *event_tap_bdrv_aio_writev(BlockDriverState *bs,
                                            int64_t sector_num,
                                            QEMUIOVector *iov,
                                            int nb_sectors,
                                            BlockDriverCompletionFunc *cb,
                                            void *opaque)
{
    BlockRequest req;
    EventTapBlkReq *ereq;

    assert(event_tap_state == EVENT_TAP_ON);

    req.sector = sector_num;
    req.nb_sectors = nb_sectors;
    req.qiov = iov;
    req.cb = cb;
    req.opaque = opaque;
    ereq = event_tap_bdrv(bs, &req, 1, 0);

    return &ereq->acb[0]->common;
}

BlockDriverAIOCB *event_tap_bdrv_aio_flush(BlockDriverState *bs,
                                           BlockDriverCompletionFunc *cb,
                                           void *opaque)
{
    BlockRequest req;
    EventTapBlkReq *ereq;

    assert(event_tap_state == EVENT_TAP_ON);

    memset(&req, 0, sizeof(req));
    req.cb = cb;
    req.opaque = opaque;
    ereq = event_tap_bdrv(bs, &req, 1, 1);

    return &ereq->acb[0]->common;
}

void event_tap_bdrv_flush(void)
{
    qemu_bh_cancel(event_tap_bh);

    while (!QTAILQ_EMPTY(&event_list)) {
        event_tap_cb();
    }
}

static void event_tap_blk_flush(EventTapBlkReq *blk_req)
{
    int i, ret;

    for (i = 0; i < blk_req->num_reqs; i++) {
        BlockRequest *req = &blk_req->reqs[i];
        EventTapAIOCB *eacb = blk_req->acb[i];
        BlockDriverAIOCB *acb = &eacb->common;

        /* don't flush if canceled */
        if (eacb->is_canceled) {
            continue;
        }

        /* receiver needs to restore bs from device name */
        if (!acb->bs) {
            acb->bs = bdrv_find(blk_req->device_name);
        }

        if (blk_req->is_flush) {
            eacb->acb = bdrv_aio_flush(acb->bs, req->cb, req->opaque);
            if (!eacb->acb) {
                req->cb(req->opaque, -EIO);
            }
            return;
        }

        eacb->acb = bdrv_aio_writev(acb->bs, req->sector, req->qiov,
                                    req->nb_sectors, req->cb, req->opaque);
        if (!eacb->acb) {
            req->cb(req->opaque, -EIO);
        }

        /* force flush to avoid request inversion */
        qemu_aio_flush();
        ret = bdrv_flush(acb->bs);
        if (ret < 0) {
            error_report("flushing blk_req to %s failed", blk_req->device_name);
        }
    }
}

static void event_tap_blk_save(QEMUFile *f, EventTapBlkReq *blk_req)
{
    ram_addr_t page_addr;
    int i, j, len;

    len = strlen(blk_req->device_name);
    qemu_put_byte(f, len);
    qemu_put_buffer(f, (uint8_t *)blk_req->device_name, len);
    qemu_put_byte(f, blk_req->num_reqs);
    qemu_put_byte(f, blk_req->is_flush);

    if (blk_req->is_flush) {
        return;
    }

    for (i = 0; i < blk_req->num_reqs; i++) {
        BlockRequest *req = &blk_req->reqs[i];
        EventTapAIOCB *eacb = blk_req->acb[i];
        /* don't save canceled requests */
        if (eacb->is_canceled) {
            continue;
        }
        qemu_put_be64(f, req->sector);
        qemu_put_be32(f, req->nb_sectors);
        qemu_put_be32(f, req->qiov->niov);

        for (j = 0; j < req->qiov->niov; j++) {
            page_addr =
                qemu_ram_addr_from_host_nofail(req->qiov->iov[j].iov_base);
            qemu_put_be64(f, page_addr);
            qemu_put_be64(f, req->qiov->iov[j].iov_len);
        }
    }
}

static void event_tap_blk_load(QEMUFile *f, EventTapBlkReq *blk_req)
{
    BlockRequest *req;
    ram_addr_t page_addr;
    int i, j, len, niov;

    len = qemu_get_byte(f);
    blk_req->device_name = qemu_malloc(len + 1);
    qemu_get_buffer(f, (uint8_t *)blk_req->device_name, len);
    blk_req->device_name[len] = '\0';
    blk_req->num_reqs = qemu_get_byte(f);
    blk_req->is_flush = qemu_get_byte(f);

    if (blk_req->is_flush) {
        return;
    }

    for (i = 0; i < blk_req->num_reqs; i++) {
        req = &blk_req->reqs[i];
        req->sector = qemu_get_be64(f);
        req->nb_sectors = qemu_get_be32(f);
        req->qiov = qemu_mallocz(sizeof(QEMUIOVector));
        niov = qemu_get_be32(f);
        qemu_iovec_init(req->qiov, niov);

        for (j = 0; j < niov; j++) {
            void *iov_base;
            size_t iov_len;
            page_addr = qemu_get_be64(f);
            iov_base = qemu_get_ram_ptr(page_addr);
            iov_len = qemu_get_be64(f);
            qemu_iovec_add(req->qiov, iov_base, iov_len);
        }
    }
}

void event_tap_ioport(int index, uint32_t address, uint32_t data)
{
    if (event_tap_state != EVENT_TAP_ON) {
        return;
    }

    if (!last_event_tap) {
        last_event_tap = event_tap_alloc_log();
    }

    last_event_tap->mode = EVENT_TAP_IOPORT;
    last_event_tap->ioport.index = index;
    last_event_tap->ioport.address = address;
    last_event_tap->ioport.data = data;
}

static inline void event_tap_ioport_save(QEMUFile *f, EventTapIOport *ioport)
{
    qemu_put_be32(f, ioport->index);
    qemu_put_be32(f, ioport->address);
    qemu_put_byte(f, ioport->data);
}

static inline void event_tap_ioport_load(QEMUFile *f,
                                         EventTapIOport *ioport)
{
    ioport->index = qemu_get_be32(f);
    ioport->address = qemu_get_be32(f);
    ioport->data = qemu_get_byte(f);
}

void event_tap_mmio(uint64_t address, uint8_t *buf, int len)
{
    if (event_tap_state != EVENT_TAP_ON || len > MMIO_BUF_SIZE) {
        return;
    }

    if (!last_event_tap) {
        last_event_tap = event_tap_alloc_log();
    }

    last_event_tap->mode = EVENT_TAP_MMIO;
    last_event_tap->mmio.address = address;
    last_event_tap->mmio.len = len;
    memcpy(last_event_tap->mmio.buf, buf, len);
}

static inline void event_tap_mmio_save(QEMUFile *f, EventTapMMIO *mmio)
{
    qemu_put_be64(f, mmio->address);
    qemu_put_byte(f, mmio->len);
    qemu_put_buffer(f, mmio->buf, mmio->len);
}

static inline void event_tap_mmio_load(QEMUFile *f, EventTapMMIO *mmio)
{
    mmio->address = qemu_get_be64(f);
    mmio->len = qemu_get_byte(f);
    qemu_get_buffer(f, mmio->buf, mmio->len);
}

int event_tap_register(int (*cb)(void))
{
    if (event_tap_state != EVENT_TAP_OFF) {
        error_report("event-tap is already on");
        return -EINVAL;
    }

    if (!cb || event_tap_cb) {
        error_report("can't set event_tap_cb");
        return -EINVAL;
    }

    event_tap_cb = cb;
    event_tap_state = EVENT_TAP_ON;

    return 0;
}

void event_tap_unregister(void)
{
    if (event_tap_state == EVENT_TAP_OFF) {
        error_report("event-tap is already off");
        return;
    }

    qemu_del_vm_change_state_handler(vmstate);

    event_tap_flush();
    event_tap_free_pool();

    event_tap_state = EVENT_TAP_OFF;
    event_tap_cb = NULL;
}

int event_tap_is_on(void)
{
    return (event_tap_state == EVENT_TAP_ON);
}

static void event_tap_suspend(void *opaque, int running, int reason)
{
    event_tap_state = running ? EVENT_TAP_ON : EVENT_TAP_SUSPEND;
}

/* returns 1 if the queue gets emtpy */
int event_tap_flush_one(void)
{
    EventTapLog *log;
    int ret;

    if (QTAILQ_EMPTY(&event_list)) {
        return 1;
    }

    event_tap_state = EVENT_TAP_FLUSH;

    log = QTAILQ_FIRST(&event_list);
    QTAILQ_REMOVE(&event_list, log, node);
    switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
    case EVENT_TAP_NET:
        event_tap_net_flush(&log->net_req);
        event_tap_free_log(log);
        break;
    case EVENT_TAP_BLK:
        event_tap_blk_flush(&log->blk_req);
        break;
    default:
        error_report("Unknown state %d", log->mode);
        event_tap_free_log(log);
        return -EINVAL;
    }

    ret = QTAILQ_EMPTY(&event_list);
    event_tap_state = ret ? EVENT_TAP_ON : EVENT_TAP_FLUSH;

    return ret;
}

void event_tap_flush(void)
{
    int ret;

    do {
        ret = event_tap_flush_one();
    } while (ret == 0);

    if (ret < 0) {
        error_report("error flushing event-tap requests");
        abort();
    }
}

static void event_tap_replay(void *opaque, int running, int reason)
{
    EventTapLog *log, *next;

    if (!running) {
        return;
    }

    assert(event_tap_state == EVENT_TAP_LOAD);

    event_tap_state = EVENT_TAP_REPLAY;

    QTAILQ_FOREACH(log, &event_list, node) {
        if ((log->mode & ~EVENT_TAP_TYPE_MASK) == EVENT_TAP_NET) {
            EventTapNetReq *net_req = &log->net_req;
            if (!net_req->async) {
                event_tap_net_flush(net_req);
                continue;
            }
        }

        switch (log->mode & EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_IOPORT:
            switch (log->ioport.index) {
            case 0:
                cpu_outb(log->ioport.address, log->ioport.data);
                break;
            case 1:
                cpu_outw(log->ioport.address, log->ioport.data);
                break;
            case 2:
                cpu_outl(log->ioport.address, log->ioport.data);
                break;
            }
            break;
        case EVENT_TAP_MMIO:
            cpu_physical_memory_rw(log->mmio.address,
                                   log->mmio.buf,
                                   log->mmio.len, 1);
            break;
        case 0:
            trace_event_tap_replay_no_event();
            break;
        default:
            error_report("Unknown state %d", log->mode);
            QTAILQ_REMOVE(&event_list, log, node);
            event_tap_free_log(log);
            return;
        }
    }

    /* remove event logs from queue */
    QTAILQ_FOREACH_SAFE(log, &event_list, node, next) {
        QTAILQ_REMOVE(&event_list, log, node);
        event_tap_free_log(log);
    }

    event_tap_state = EVENT_TAP_OFF;
    qemu_del_vm_change_state_handler(vmstate);
}

static void event_tap_save(QEMUFile *f, void *opaque)
{
    EventTapLog *log;

    QTAILQ_FOREACH(log, &event_list, node) {
        qemu_put_byte(f, log->mode);

        switch (log->mode & EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_IOPORT:
            event_tap_ioport_save(f, &log->ioport);
            break;
        case EVENT_TAP_MMIO:
            event_tap_mmio_save(f, &log->mmio);
            break;
        case 0:
            trace_event_tap_save_no_event();
            break;
        default:
            error_report("Unknown state %d", log->mode);
            return;
        }

        switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_NET:
            event_tap_net_save(f, &log->net_req);
            break;
        case EVENT_TAP_BLK:
            event_tap_blk_save(f, &log->blk_req);
            break;
        default:
            error_report("Unknown state %d", log->mode);
            return;
        }
    }

    qemu_put_byte(f, 0); /* EOF */
}

static int event_tap_load(QEMUFile *f, void *opaque, int version_id)
{
    EventTapLog *log, *next;
    int mode;

    event_tap_state = EVENT_TAP_LOAD;

    QTAILQ_FOREACH_SAFE(log, &event_list, node, next) {
        QTAILQ_REMOVE(&event_list, log, node);
        event_tap_free_log(log);
    }

    /* loop until EOF */
    while ((mode = qemu_get_byte(f)) != 0) {
        EventTapLog *log = event_tap_alloc_log();

        log->mode = mode;
        switch (log->mode & EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_IOPORT:
            event_tap_ioport_load(f, &log->ioport);
            break;
        case EVENT_TAP_MMIO:
            event_tap_mmio_load(f, &log->mmio);
            break;
        case 0:
            trace_event_tap_load_no_event();
            break;
        default:
            error_report("Unknown state %d", log->mode);
            event_tap_free_log(log);
            return -EINVAL;
        }

        switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_NET:
            event_tap_net_load(f, &log->net_req);
            break;
        case EVENT_TAP_BLK:
            event_tap_blk_load(f, &log->blk_req);
            break;
        default:
            error_report("Unknown state %d", log->mode);
            event_tap_free_log(log);
            return -EINVAL;
        }

        QTAILQ_INSERT_TAIL(&event_list, log, node);
    }

    return 0;
}

void event_tap_schedule_replay(void)
{
    vmstate = qemu_add_vm_change_state_handler(event_tap_replay, NULL);
}

void event_tap_schedule_suspend(void)
{
    vmstate = qemu_add_vm_change_state_handler(event_tap_suspend, NULL);
}

void event_tap_init(void)
{
    QTAILQ_INIT(&event_list);
    QTAILQ_INIT(&event_pool);
    register_savevm(NULL, "event-tap", 0, 1,
                    event_tap_save, event_tap_load, &last_event_tap);
}
