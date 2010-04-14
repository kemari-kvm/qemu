/*
 * Fault tolerant VM transaction QEMUFile
 *
 * Copyright (c) 2010 Nippon Telegraph and Telephone Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * This source code is based on buffered_file.h.
 * Copyright IBM, Corp. 2008
 * Authors:
 *  Anthony Liguori        <aliguori@us.ibm.com>
 */

#ifndef QEMU_FT_TRANSACTION_FILE_H
#define QEMU_FT_TRANSACTION_FILE_H

#include "hw/hw.h"

enum QEMU_VM_TRANSACTION_STATE {
    QEMU_VM_TRANSACTION_NACK = -1,
    QEMU_VM_TRANSACTION_INIT,
    QEMU_VM_TRANSACTION_BEGIN,
    QEMU_VM_TRANSACTION_CONTINUE,
    QEMU_VM_TRANSACTION_COMMIT,
    QEMU_VM_TRANSACTION_CANCEL,
    QEMU_VM_TRANSACTION_ATOMIC,
    QEMU_VM_TRANSACTION_ACK,
};

enum FT_MODE {
    FT_ERROR = -1,
    FT_OFF,
    FT_INIT,
    FT_TRANSACTION_BEGIN,
    FT_TRANSACTION_ITER,
    FT_TRANSACTION_COMMIT,
    FT_TRANSACTION_ATOMIC,
    FT_TRANSACTION_RECV,
};
extern enum FT_MODE ft_mode;

#define FT_TRANS_ERR_UNKNOWN       0x01 /* Unknown error */
#define FT_TRANS_ERR_SEND_HDR      0x02 /* Send header failed */
#define FT_TRANS_ERR_RECV_HDR      0x03 /* Recv header failed */
#define FT_TRANS_ERR_SEND_PAYLOAD  0x04 /* Send payload failed */
#define FT_TRANS_ERR_RECV_PAYLOAD  0x05 /* Recv payload failed */
#define FT_TRANS_ERR_FLUSH         0x06 /* Flush buffered data failed */
#define FT_TRANS_ERR_STATE_INVALID 0x07 /* Invalid state */

typedef ssize_t (FtTransPutBufferFunc)(void *opaque, const void *data, size_t size);
typedef int (FtTransGetBufferFunc)(void *opaque, uint8_t *buf, int64_t pos, size_t size);
typedef ssize_t (FtTransPutVectorFunc)(void *opaque, const struct iovec *iov, int iovcnt);
typedef int (FtTransPutReadyFunc)(void);
typedef int (FtTransGetReadyFunc)(void *opaque);
typedef void (FtTransWaitForUnfreezeFunc)(void *opaque);
typedef int (FtTransCloseFunc)(void *opaque);

int ft_trans_begin(void *opaque);
int ft_trans_commit(void *opaque);
int ft_trans_cancel(void *opaque);

QEMUFile *qemu_fopen_ops_ft_trans(void *opaque,
                                  FtTransPutBufferFunc *put_buffer,
                                  FtTransGetBufferFunc *get_buffer,
                                  FtTransPutReadyFunc *put_ready,
                                  FtTransGetReadyFunc *get_ready,
                                  FtTransWaitForUnfreezeFunc *wait_for_unfreeze,
                                  FtTransCloseFunc *close,
                                  bool is_sender);

#endif
