/*
 * Event Tap functions for QEMU
 *
 * Copyright (c) 2010 Nippon Telegraph and Telephone Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef EVENT_TAP_H
#define EVENT_TAP_H

#include "qemu-common.h"
#include "net.h"
#include "block.h"

int event_tap_register(int (*cb)(void));
void event_tap_unregister(void);
int event_tap_is_on(void);
void event_tap_schedule_suspend(void);
void event_tap_ioport(int index, uint32_t address, uint32_t data);
void event_tap_mmio(uint64_t address, uint8_t *buf, int len);
void event_tap_init(void);
void event_tap_flush(void);
int event_tap_flush_one(void);
void event_tap_schedule_replay(void);

void event_tap_send_packet(VLANClientState *vc, const uint8_t *buf, int size);
ssize_t event_tap_sendv_packet_async(VLANClientState *vc,
                                     const struct iovec *iov,
                                     int iovcnt, NetPacketSent *sent_cb);

BlockDriverAIOCB *event_tap_bdrv_aio_writev(BlockDriverState *bs,
                                            int64_t sector_num,
                                            QEMUIOVector *iov,
                                            int nb_sectors,
                                            BlockDriverCompletionFunc *cb,
                                            void *opaque);
BlockDriverAIOCB *event_tap_bdrv_aio_flush(BlockDriverState *bs,
                                           BlockDriverCompletionFunc *cb,
                                           void *opaque);
void event_tap_bdrv_flush(void);

#endif
