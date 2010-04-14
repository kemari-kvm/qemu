/*
 * Fault tolerant VM transaction QEMUFile
 *
 * Copyright (c) 2010 Nippon Telegraph and Telephone Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * This source code is based on buffered_file.c.
 * Copyright IBM, Corp. 2008
 * Authors:
 *  Anthony Liguori        <aliguori@us.ibm.com>
 */

#include "qemu-common.h"
#include "qemu-error.h"
#include "hw/hw.h"
#include "qemu-timer.h"
#include "sysemu.h"
#include "qemu-char.h"
#include "trace.h"
#include "ft_trans_file.h"

typedef struct FtTransHdr
{
    uint16_t cmd;
    uint16_t id;
    uint32_t seq;
    uint32_t payload_len;
} FtTransHdr;

typedef struct QEMUFileFtTrans
{
    FtTransPutBufferFunc *put_buffer;
    FtTransGetBufferFunc *get_buffer;
    FtTransPutReadyFunc *put_ready;
    FtTransGetReadyFunc *get_ready;
    FtTransWaitForUnfreezeFunc *wait_for_unfreeze;
    FtTransCloseFunc *close;
    void *opaque;
    QEMUFile *file;

    enum QEMU_VM_TRANSACTION_STATE state;
    uint32_t seq;
    uint16_t id;

    int has_error;

    bool freeze_output;
    bool freeze_input;
    bool rate_limit;
    bool is_sender;
    bool is_payload;

    uint8_t *buf;
    size_t buf_max_size;
    size_t put_offset;
    size_t get_offset;

    FtTransHdr header;
    size_t header_offset;
} QEMUFileFtTrans;

#define IO_BUF_SIZE 32768

static void ft_trans_append(QEMUFileFtTrans *s,
                            const uint8_t *buf, size_t size)
{
    if (size > (s->buf_max_size - s->put_offset)) {
        trace_ft_trans_realloc(s->buf_max_size, size + 1024);
        s->buf_max_size += size + 1024;
        s->buf = qemu_realloc(s->buf, s->buf_max_size);
    }

    trace_ft_trans_append(size);
    memcpy(s->buf + s->put_offset, buf, size);
    s->put_offset += size;
}

static void ft_trans_flush(QEMUFileFtTrans *s)
{
    size_t offset = 0;

    if (s->has_error) {
        error_report("flush when error %d, bailing", s->has_error);
        return;
    }

    while (offset < s->put_offset) {
        ssize_t ret;

        ret = s->put_buffer(s->opaque, s->buf + offset, s->put_offset - offset);
        if (ret == -EAGAIN) {
            break;
        }

        if (ret <= 0) {
            error_report("error flushing data, %s", strerror(errno));
            s->has_error = FT_TRANS_ERR_FLUSH;
            break;
        } else {
            offset += ret;
        }
    }

    trace_ft_trans_flush(offset, s->put_offset);
    memmove(s->buf, s->buf + offset, s->put_offset - offset);
    s->put_offset -= offset;
    s->freeze_output = !!s->put_offset;
}

static ssize_t ft_trans_put(void *opaque, void *buf, int size)
{
    QEMUFileFtTrans *s = opaque;
    size_t offset = 0;
    ssize_t len;

    /* flush buffered data before putting next */
    if (s->put_offset) {
        ft_trans_flush(s);
    }

    while (!s->freeze_output && offset < size) {
        len = s->put_buffer(s->opaque, (uint8_t *)buf + offset, size - offset);

        if (len == -EAGAIN) {
            trace_ft_trans_freeze_output();
            s->freeze_output = 1;
            break;
        }

        if (len <= 0) {
            error_report("putting data failed, %s", strerror(errno));
            s->has_error = 1;
            offset = -EINVAL;
            break;
        }

        offset += len;
    }

    if (s->freeze_output) {
        ft_trans_append(s, buf + offset, size - offset);
        offset = size;
    }

    return offset;
}

static int ft_trans_send_header(QEMUFileFtTrans *s,
                                enum QEMU_VM_TRANSACTION_STATE state,
                                uint32_t payload_len)
{
    int ret;
    FtTransHdr *hdr = &s->header;

    trace_ft_trans_send_header(state);

    hdr->cmd = s->state = state;
    hdr->id = s->id;
    hdr->seq = s->seq;
    hdr->payload_len = payload_len;

    ret = ft_trans_put(s, hdr, sizeof(*hdr));
    if (ret < 0) {
        error_report("send header failed");
        s->has_error = FT_TRANS_ERR_SEND_HDR;
    }

    return ret;
}

static int ft_trans_put_buffer(void *opaque, const uint8_t *buf, int64_t pos, int size)
{
    QEMUFileFtTrans *s = opaque;
    ssize_t ret;

    trace_ft_trans_put_buffer(size, pos);

    if (s->has_error) {
        error_report("put_buffer when error %d, bailing", s->has_error);
        return -EINVAL;
    }

    /* assuming qemu_file_put_notify() is calling */
    if (pos == 0 && size == 0) {
        trace_ft_trans_put_ready();
        ft_trans_flush(s);

        if (!s->freeze_output) {
            trace_ft_trans_cb(s->put_ready);
            ret = s->put_ready();
        }

        ret = 0;
        goto out;
    }

    ret = ft_trans_send_header(s, QEMU_VM_TRANSACTION_CONTINUE, size);
    if (ret < 0) {
        goto out;
    }

    ret = ft_trans_put(s, (uint8_t *)buf, size);
    if (ret < 0) {
        error_report("send palyload failed");
        s->has_error = FT_TRANS_ERR_SEND_PAYLOAD;
        goto out;
    }

    s->seq++;

out:
    return ret;
}

static int ft_trans_fill_buffer(void *opaque, void *buf, int size)
{
    QEMUFileFtTrans *s = opaque;
    size_t offset = 0;
    ssize_t len;

    s->freeze_input = 0;

    while (offset < size) {
        len = s->get_buffer(s->opaque, (uint8_t *)buf + offset,
                            0, size - offset);
        if (len == -EAGAIN) {
            trace_ft_trans_freeze_input();
            s->freeze_input = 1;
            break;
        }

        if (len <= 0) {
            error_report("fill buffer failed, %s", strerror(errno));
            s->has_error = 1;
            return -EINVAL;
        }

        offset += len;
    }

    return offset;
}

static int ft_trans_recv_header(QEMUFileFtTrans *s)
{
    int ret;
    char *buf = (char *)&s->header + s->header_offset;

    ret = ft_trans_fill_buffer(s, buf, sizeof(FtTransHdr) - s->header_offset);
    if (ret < 0) {
        error_report("recv header failed");
        s->has_error = FT_TRANS_ERR_RECV_HDR;
        goto out;
    }

    s->header_offset += ret;
    if (s->header_offset == sizeof(FtTransHdr)) {
        trace_ft_trans_recv_header(s->header.cmd);
        s->state = s->header.cmd;
        s->header_offset = 0;

        if (!s->is_sender) {
            s->id = s->header.id;
            s->seq = s->header.seq;
        }
    }

out:
    return ret;
}

static int ft_trans_recv_payload(QEMUFileFtTrans *s)
{
    QEMUFile *f = s->file;
    int ret = -1;

    /* extend QEMUFile buf if there weren't enough space */
    if (s->header.payload_len > (s->buf_max_size - s->get_offset)) {
        s->buf_max_size += (s->header.payload_len -
                            (s->buf_max_size - s->get_offset));
        s->buf = qemu_realloc_buffer(f, s->buf_max_size);
    }

    ret = ft_trans_fill_buffer(s, s->buf + s->get_offset,
                               s->header.payload_len);
    if (ret < 0) {
        error_report("recv payload failed");
        s->has_error = FT_TRANS_ERR_RECV_PAYLOAD;
        goto out;
    }

    trace_ft_trans_recv_payload(ret, s->header.payload_len, s->get_offset);

    s->header.payload_len -= ret;
    s->get_offset += ret;
    s->is_payload = !!s->header.payload_len;

out:
    return ret;
}

static int ft_trans_recv(QEMUFileFtTrans *s)
{
    int ret;

    /* get payload and return */
    if (s->is_payload) {
        ret = ft_trans_recv_payload(s);
        goto out;
    }

    ret = ft_trans_recv_header(s);
    if (ret < 0 || s->freeze_input) {
        goto out;
    }

    switch (s->state) {
    case QEMU_VM_TRANSACTION_BEGIN:
        /* CONTINUE or COMMIT should come shortly */
        s->is_payload = 0;
        break;

    case QEMU_VM_TRANSACTION_CONTINUE:
        /* get payload */
        s->is_payload = 1;
        break;

    case QEMU_VM_TRANSACTION_COMMIT:
        ret = ft_trans_send_header(s, QEMU_VM_TRANSACTION_ACK, 0);
        if (ret < 0) {
            goto out;
        }

        trace_ft_trans_cb(s->get_ready);
        ret = s->get_ready(s->opaque);
        if (ret < 0) {
            goto out;
        }

        qemu_clear_buffer(s->file);
        s->get_offset = 0;
        s->is_payload = 0;

        break;

    case QEMU_VM_TRANSACTION_ATOMIC:
        /* not implemented yet */
        error_report("QEMU_VM_TRANSACTION_ATOMIC not implemented. %d",
                ret);
        break;

    case QEMU_VM_TRANSACTION_CANCEL:
        /* return -EINVAL until migrate cancel on recevier side is supported */
        ret = -EINVAL;
        break;

    default:
        error_report("unknown QEMU_VM_TRANSACTION_STATE %d", ret);
        s->has_error = FT_TRANS_ERR_STATE_INVALID;
        ret = -EINVAL;
    }

out:
    return ret;
}

static int ft_trans_get_buffer(void *opaque, uint8_t *buf,
                               int64_t pos, int size)
{
    QEMUFileFtTrans *s = opaque;
    int ret;

    if (s->has_error) {
        error_report("get_buffer when error %d, bailing", s->has_error);
        return -EINVAL;
    }

    /* assuming qemu_file_get_notify() is calling */
    if (pos == 0 && size == 0) {
        trace_ft_trans_get_ready();
        s->freeze_input = 0;

        /* sender should be waiting for ACK */
        if (s->is_sender) {
            ret = ft_trans_recv_header(s);
            if (s->freeze_input) {
                ret = 0;
                goto out;
            }
            if (ret < 0) {
                error_report("recv ack failed");
                goto out;
            }

            if (s->state != QEMU_VM_TRANSACTION_ACK) {
                error_report("recv invalid state %d", s->state);
                s->has_error = FT_TRANS_ERR_STATE_INVALID;
                ret = -EINVAL;
                goto out;
            }

            trace_ft_trans_cb(s->get_ready);
            ret = s->get_ready(s->opaque);
            if (ret < 0) {
                goto out;
            }

            /* proceed trans id */
            s->id++;

            return 0;
        }

        /* set QEMUFile buf at beginning */
        if (!s->buf) {
            s->buf = buf;
        }

        ret = ft_trans_recv(s);
        goto out;
    }

    ret = s->get_offset;

out:
    return ret;
}

static int ft_trans_close(void *opaque)
{
    QEMUFileFtTrans *s = opaque;
    int ret;

    trace_ft_trans_close();
    ret = s->close(s->opaque);
    if (s->is_sender) {
        qemu_free(s->buf);
    }
    qemu_free(s);

    return ret;
}

static int ft_trans_rate_limit(void *opaque)
{
    QEMUFileFtTrans *s = opaque;

    if (s->has_error) {
        return 0;
    }

    if (s->rate_limit && s->freeze_output) {
        return 1;
    }

    return 0;
}

static int64_t ft_trans_set_rate_limit(void *opaque, int64_t new_rate)
{
    QEMUFileFtTrans *s = opaque;

    if (s->has_error) {
        goto out;
    }

    s->rate_limit = !!new_rate;

out:
    return s->rate_limit;
}

int ft_trans_begin(void *opaque)
{
    QEMUFileFtTrans *s = opaque;
    int ret;
    s->seq = 0;

    /* receiver sends QEMU_VM_TRANSACTION_ACK to start transaction */
    if (!s->is_sender) {
        if (s->state != QEMU_VM_TRANSACTION_INIT) {
            error_report("invalid state %d", s->state);
            s->has_error = FT_TRANS_ERR_STATE_INVALID;
            ret = -EINVAL;
        }

        ret = ft_trans_send_header(s, QEMU_VM_TRANSACTION_ACK, 0);
        goto out;
    }

    /* sender waits for QEMU_VM_TRANSACTION_ACK to start transaction */
    if (s->state == QEMU_VM_TRANSACTION_INIT) {
retry:
        ret = ft_trans_recv_header(s);
        if (s->freeze_input) {
            goto retry;
        }
        if (ret < 0) {
            error_report("recv ack failed");
            goto out;
        }

        if (s->state != QEMU_VM_TRANSACTION_ACK) {
            error_report("recv invalid state %d", s->state);
            s->has_error = FT_TRANS_ERR_STATE_INVALID;
            ret = -EINVAL;
            goto out;
        }
    }

    ret = ft_trans_send_header(s, QEMU_VM_TRANSACTION_BEGIN, 0);
    if (ret < 0) {
        goto out;
    }

    s->state = QEMU_VM_TRANSACTION_CONTINUE;

out:
    return ret;
}

int ft_trans_commit(void *opaque)
{
    QEMUFileFtTrans *s = opaque;
    int ret;

    if (!s->is_sender) {
        ret = ft_trans_send_header(s, QEMU_VM_TRANSACTION_ACK, 0);
        goto out;
    }

    /* sender should flush buf before sending COMMIT */
    qemu_fflush(s->file);

    ret = ft_trans_send_header(s, QEMU_VM_TRANSACTION_COMMIT, 0);
    if (ret < 0) {
        goto out;
    }

    while (!s->has_error && s->put_offset) {
        ft_trans_flush(s);
        if (s->freeze_output) {
            s->wait_for_unfreeze(s);
        }
    }

    if (s->has_error) {
        ret = -EINVAL;
        goto out;
    }

    ret = ft_trans_recv_header(s);
    if (s->freeze_input) {
        ret = -EAGAIN;
        goto out;
    }
    if (ret < 0) {
        error_report("recv ack failed");
        goto out;
    }

    if (s->state != QEMU_VM_TRANSACTION_ACK) {
        error_report("recv invalid state %d", s->state);
        s->has_error = FT_TRANS_ERR_STATE_INVALID;
        ret = -EINVAL;
        goto out;
    }

    s->id++;
    ret = 0;

out:
    return ret;
}

int ft_trans_cancel(void *opaque)
{
    QEMUFileFtTrans *s = opaque;

    /* invalid until migrate cancel on recevier side is supported */
    if (!s->is_sender) {
        return -EINVAL;
    }

    return ft_trans_send_header(s, QEMU_VM_TRANSACTION_CANCEL, 0);
}

QEMUFile *qemu_fopen_ops_ft_trans(void *opaque,
                                  FtTransPutBufferFunc *put_buffer,
                                  FtTransGetBufferFunc *get_buffer,
                                  FtTransPutReadyFunc *put_ready,
                                  FtTransGetReadyFunc *get_ready,
                                  FtTransWaitForUnfreezeFunc *wait_for_unfreeze,
                                  FtTransCloseFunc *close,
                                  bool is_sender)
{
    QEMUFileFtTrans *s;

    s = qemu_mallocz(sizeof(*s));

    s->opaque = opaque;
    s->put_buffer = put_buffer;
    s->get_buffer = get_buffer;
    s->put_ready = put_ready;
    s->get_ready = get_ready;
    s->wait_for_unfreeze = wait_for_unfreeze;
    s->close = close;
    s->is_sender = is_sender;
    s->id = 0;
    s->seq = 0;
    s->rate_limit = 1;

    if (!s->is_sender) {
        s->buf_max_size = IO_BUF_SIZE;
    }

    s->file = qemu_fopen_ops(s, ft_trans_put_buffer, ft_trans_get_buffer,
                             ft_trans_close, ft_trans_rate_limit,
                             ft_trans_set_rate_limit, NULL);

    return s->file;
}
