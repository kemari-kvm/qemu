/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "migration.h"
#include "monitor.h"
#include "buffered_file.h"
#include "ft_trans_file.h"
#include "sysemu.h"
#include "block.h"
#include "qemu_socket.h"
#include "block-migration.h"
#include "qemu-objects.h"
#include "event-tap.h"

//#define DEBUG_MIGRATION

#ifdef DEBUG_MIGRATION
#define DPRINTF(fmt, ...) \
    do { printf("migration: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

enum FT_MODE ft_mode = FT_OFF;

/* Migration speed throttling */
static int64_t max_throttle = (32 << 20);

static MigrationState *current_migration;

static NotifierList migration_state_notifiers =
    NOTIFIER_LIST_INITIALIZER(migration_state_notifiers);

int qemu_start_incoming_migration(const char *uri)
{
    const char *p;
    int ret;

    /* check ft_mode (Kemari protocol) */
    if (strstart(uri, "kemari:", &p)) {
        ft_mode = FT_INIT;
        uri = p;
    }

    if (strstart(uri, "tcp:", &p))
        ret = tcp_start_incoming_migration(p);
#if !defined(WIN32)
    else if (strstart(uri, "exec:", &p))
        ret =  exec_start_incoming_migration(p);
    else if (strstart(uri, "unix:", &p))
        ret = unix_start_incoming_migration(p);
    else if (strstart(uri, "fd:", &p))
        ret = fd_start_incoming_migration(p);
#endif
    else {
        fprintf(stderr, "unknown migration protocol: %s\n", uri);
        ret = -EPROTONOSUPPORT;
    }
    return ret;
}

void process_incoming_migration(QEMUFile *f)
{
    if (qemu_loadvm_state(f) < 0) {
        fprintf(stderr, "load of migration failed\n");
        exit(0);
    }
    qemu_announce_self();
    DPRINTF("successfully loaded vm state\n");

    incoming_expected = false;

    if (autostart)
        vm_start();
}

int do_migrate(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    MigrationState *s = NULL;
    const char *p;
    int detach = qdict_get_try_bool(qdict, "detach", 0);
    int blk = qdict_get_try_bool(qdict, "blk", 0);
    int inc = qdict_get_try_bool(qdict, "inc", 0);
    const char *uri = qdict_get_str(qdict, "uri");

    if (current_migration &&
        current_migration->get_status(current_migration) == MIG_STATE_ACTIVE) {
        monitor_printf(mon, "migration already in progress\n");
        return -1;
    }

    if (qemu_savevm_state_blocked(mon)) {
        return -1;
    }

    /* check ft_mode (Kemari protocol) */
    if (strstart(uri, "kemari:", &p)) {
        ft_mode = FT_INIT;
        uri = p;
    }

    if (strstart(uri, "tcp:", &p)) {
        s = tcp_start_outgoing_migration(mon, p, max_throttle, detach,
                                         blk, inc);
#if !defined(WIN32)
    } else if (strstart(uri, "exec:", &p)) {
        s = exec_start_outgoing_migration(mon, p, max_throttle, detach,
                                          blk, inc);
    } else if (strstart(uri, "unix:", &p)) {
        s = unix_start_outgoing_migration(mon, p, max_throttle, detach,
                                          blk, inc);
    } else if (strstart(uri, "fd:", &p)) {
        s = fd_start_outgoing_migration(mon, p, max_throttle, detach, 
                                        blk, inc);
#endif
    } else {
        monitor_printf(mon, "unknown migration protocol: %s\n", uri);
        return -1;
    }

    if (s == NULL) {
        monitor_printf(mon, "migration failed\n");
        return -1;
    }

    if (current_migration) {
        current_migration->release(current_migration);
    }

    current_migration = s;
    notifier_list_notify(&migration_state_notifiers);
    return 0;
}

int do_migrate_cancel(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    MigrationState *s = current_migration;

    if (s)
        s->cancel(s);

    return 0;
}

int do_migrate_set_speed(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    int64_t d;
    FdMigrationState *s;

    d = qdict_get_int(qdict, "value");
    if (d < 0) {
        d = 0;
    }
    max_throttle = d;

    s = migrate_to_fms(current_migration);
    if (s && s->file) {
        qemu_file_set_rate_limit(s->file, max_throttle);
    }

    return 0;
}

/* amount of nanoseconds we are willing to wait for migration to be down.
 * the choice of nanoseconds is because it is the maximum resolution that
 * get_clock() can achieve. It is an internal measure. All user-visible
 * units must be in seconds */
static uint64_t max_downtime = 30000000;

uint64_t migrate_max_downtime(void)
{
    return max_downtime;
}

int do_migrate_set_downtime(Monitor *mon, const QDict *qdict,
                            QObject **ret_data)
{
    double d;

    d = qdict_get_double(qdict, "value") * 1e9;
    d = MAX(0, MIN(UINT64_MAX, d));
    max_downtime = (uint64_t)d;

    return 0;
}

static void migrate_print_status(Monitor *mon, const char *name,
                                 const QDict *status_dict)
{
    QDict *qdict;

    qdict = qobject_to_qdict(qdict_get(status_dict, name));

    monitor_printf(mon, "transferred %s: %" PRIu64 " kbytes\n", name,
                        qdict_get_int(qdict, "transferred") >> 10);
    monitor_printf(mon, "remaining %s: %" PRIu64 " kbytes\n", name,
                        qdict_get_int(qdict, "remaining") >> 10);
    monitor_printf(mon, "total %s: %" PRIu64 " kbytes\n", name,
                        qdict_get_int(qdict, "total") >> 10);
}

void do_info_migrate_print(Monitor *mon, const QObject *data)
{
    QDict *qdict;

    qdict = qobject_to_qdict(data);

    monitor_printf(mon, "Migration status: %s\n",
                   qdict_get_str(qdict, "status"));

    if (qdict_haskey(qdict, "ram")) {
        migrate_print_status(mon, "ram", qdict);
    }

    if (qdict_haskey(qdict, "disk")) {
        migrate_print_status(mon, "disk", qdict);
    }
}

static void migrate_put_status(QDict *qdict, const char *name,
                               uint64_t trans, uint64_t rem, uint64_t total)
{
    QObject *obj;

    obj = qobject_from_jsonf("{ 'transferred': %" PRId64 ", "
                               "'remaining': %" PRId64 ", "
                               "'total': %" PRId64 " }", trans, rem, total);
    qdict_put_obj(qdict, name, obj);
}

void do_info_migrate(Monitor *mon, QObject **ret_data)
{
    QDict *qdict;
    MigrationState *s = current_migration;

    if (s) {
        switch (s->get_status(s)) {
        case MIG_STATE_ACTIVE:
            qdict = qdict_new();
            qdict_put(qdict, "status", qstring_from_str("active"));

            migrate_put_status(qdict, "ram", ram_bytes_transferred(),
                               ram_bytes_remaining(), ram_bytes_total());

            if (blk_mig_active()) {
                migrate_put_status(qdict, "disk", blk_mig_bytes_transferred(),
                                   blk_mig_bytes_remaining(),
                                   blk_mig_bytes_total());
            }

            *ret_data = QOBJECT(qdict);
            break;
        case MIG_STATE_COMPLETED:
            *ret_data = qobject_from_jsonf("{ 'status': 'completed' }");
            break;
        case MIG_STATE_ERROR:
            *ret_data = qobject_from_jsonf("{ 'status': 'failed' }");
            break;
        case MIG_STATE_CANCELLED:
            *ret_data = qobject_from_jsonf("{ 'status': 'cancelled' }");
            break;
        }
    }
}

/* shared migration helpers */

void migrate_fd_monitor_suspend(FdMigrationState *s, Monitor *mon)
{
    s->mon = mon;
    if (monitor_suspend(mon) == 0) {
        DPRINTF("suspending monitor\n");
    } else {
        monitor_printf(mon, "terminal does not allow synchronous "
                       "migration, continuing detached\n");
    }
}

void migrate_fd_error(FdMigrationState *s)
{
    DPRINTF("setting error state\n");
    s->state = MIG_STATE_ERROR;
    notifier_list_notify(&migration_state_notifiers);
    migrate_fd_cleanup(s);
}

static void migrate_ft_trans_error(FdMigrationState *s)
{
    ft_mode = FT_ERROR;
    qemu_savevm_state_cancel(s->mon, s->file);
    migrate_fd_error(s);
    /* we need to set vm running to avoid assert in virtio-net */
    vm_start();
    event_tap_unregister();
    vm_stop(0);
}

int migrate_fd_cleanup(FdMigrationState *s)
{
    int ret = 0;

    qemu_set_fd_handler2(s->fd, NULL, NULL, NULL, NULL);

    if (s->file) {
        DPRINTF("closing file\n");
        if (qemu_fclose(s->file) != 0) {
            ret = -1;
        }
        s->file = NULL;
    }

    if (s->fd != -1)
        close(s->fd);

    /* Don't resume monitor until we've flushed all of the buffers */
    if (s->mon) {
        monitor_resume(s->mon);
    }

    s->fd = -1;

    return ret;
}

void migrate_fd_put_notify(void *opaque)
{
    FdMigrationState *s = opaque;

    qemu_set_fd_handler2(s->fd, NULL, NULL, NULL, NULL);
    qemu_file_put_notify(s->file);
}

static void migrate_fd_get_notify(void *opaque)
{
    FdMigrationState *s = opaque;

    qemu_set_fd_handler2(s->fd, NULL, NULL, NULL, NULL);
    qemu_file_get_notify(s->file);
    if (qemu_file_has_error(s->file)) {
        migrate_ft_trans_error(s);
    }
}

ssize_t migrate_fd_put_buffer(void *opaque, const void *data, size_t size)
{
    FdMigrationState *s = opaque;
    ssize_t ret;

    do {
        ret = s->write(s, data, size);
    } while (ret == -1 && ((s->get_error(s)) == EINTR));

    if (ret == -1)
        ret = -(s->get_error(s));

    if (ret == -EAGAIN) {
        qemu_set_fd_handler2(s->fd, NULL, NULL, migrate_fd_put_notify, s);
    } else if (ret < 0) {
        if (s->mon) {
            monitor_resume(s->mon);
        }
        s->state = MIG_STATE_ERROR;
        notifier_list_notify(&migration_state_notifiers);
    }

    return ret;
}

int migrate_fd_get_buffer(void *opaque, uint8_t *data, int64_t pos, size_t size)
{
    FdMigrationState *s = opaque;
    int ret;

    ret = s->read(s, data, size);
    if (ret == -1) {
        ret = -(s->get_error(s));
    }

    if (ret == -EAGAIN) {
        qemu_set_fd_handler2(s->fd, NULL, migrate_fd_get_notify, NULL, s);
    }

    return ret;
}

void migrate_fd_connect(FdMigrationState *s)
{
    int ret;

    s->file = qemu_fopen_ops_buffered(s,
                                      s->bandwidth_limit,
                                      migrate_fd_put_buffer,
                                      migrate_fd_put_ready,
                                      migrate_fd_wait_for_unfreeze,
                                      migrate_fd_close);

    DPRINTF("beginning savevm\n");
    ret = qemu_savevm_state_begin(s->mon, s->file, s->mig_state.blk,
                                  s->mig_state.shared);
    if (ret < 0) {
        DPRINTF("failed, %d\n", ret);
        migrate_fd_error(s);
        return;
    }
    
    migrate_fd_put_ready(s);
}

static int migrate_ft_trans_commit(void *opaque)
{
    FdMigrationState *s = opaque;
    int ret = -1;

    if (ft_mode != FT_TRANSACTION_COMMIT && ft_mode != FT_TRANSACTION_ATOMIC) {
        fprintf(stderr,
                "migrate_ft_trans_commit: invalid ft_mode %d\n", ft_mode);
        goto out;
    }

    do {
        if (ft_mode == FT_TRANSACTION_ATOMIC) {
            if (qemu_ft_trans_begin(s->file) < 0) {
                fprintf(stderr, "qemu_ft_trans_begin failed\n");
                goto out;
            }

            ret = qemu_savevm_trans_begin(s->mon, s->file, 0);
            if (ret < 0) {
                fprintf(stderr, "qemu_savevm_trans_begin failed\n");
                goto out;
            }

            ft_mode = FT_TRANSACTION_COMMIT;
            if (ret) {
                /* don't proceed until if fd isn't ready */
                goto out;
            }
        }

        /* make the VM state consistent by flushing outstanding events */
        vm_stop(0);

        /* send at full speed */
        qemu_file_set_rate_limit(s->file, 0);

        ret = qemu_savevm_trans_complete(s->mon, s->file);
        if (ret < 0) {
            fprintf(stderr, "qemu_savevm_trans_complete failed\n");
            goto out;
        }

        ret = qemu_ft_trans_commit(s->file);
        if (ret < 0) {
            fprintf(stderr, "qemu_ft_trans_commit failed\n");
            goto out;
        }

        if (ret) {
            ft_mode = FT_TRANSACTION_RECV;
            ret = 1;
            goto out;
        }

        /* flush and check if events are remaining */
        vm_start();
        ret = event_tap_flush_one();
        if (ret < 0) {
            fprintf(stderr, "event_tap_flush_one failed\n");
            goto out;
        }

        ft_mode =  ret ? FT_TRANSACTION_BEGIN : FT_TRANSACTION_ATOMIC;
    } while (ft_mode != FT_TRANSACTION_BEGIN);

    vm_start();
    ret = 0;

out:
    return ret;
}

static int migrate_ft_trans_get_ready(void *opaque)
{
    FdMigrationState *s = opaque;
    int ret = -1;

    if (ft_mode != FT_TRANSACTION_RECV) {
        fprintf(stderr,
                "migrate_ft_trans_get_ready: invalid ft_mode %d\n", ft_mode);
        goto error_out;
    }

    /* flush and check if events are remaining */
    vm_start();
    ret = event_tap_flush_one();
    if (ret < 0) {
        fprintf(stderr, "event_tap_flush_one failed\n");
        goto error_out;
    }

    if (ret) {
        ft_mode = FT_TRANSACTION_BEGIN;
    } else {
        ft_mode = FT_TRANSACTION_ATOMIC;

        ret = migrate_ft_trans_commit(s);
        if (ret < 0) {
            goto error_out;
        }
        if (ret) {
            goto out;
        }
    }

    vm_start();
    ret = 0;
    goto out;

error_out:
    migrate_ft_trans_error(s);

out:
    return ret;
}

static int migrate_ft_trans_put_ready(void)
{
    FdMigrationState *s = migrate_to_fms(current_migration);
    int ret = -1, init = 0, timeout;
    static int64_t start, now;

    switch (ft_mode) {
    case FT_INIT:
        init = 1;
        ft_mode = FT_TRANSACTION_BEGIN;
    case FT_TRANSACTION_BEGIN:
        now = start = qemu_get_clock_ns(vm_clock);
        /* start transatcion at best effort */
        qemu_file_set_rate_limit(s->file, 1);

        if (qemu_ft_trans_begin(s->file) < 0) {
            fprintf(stderr, "qemu_transaction_begin failed\n");
            goto error_out;
        }

        vm_stop(0);

        ret = qemu_savevm_trans_begin(s->mon, s->file, init);
        if (ret < 0) {
            fprintf(stderr, "qemu_savevm_trans_begin\n");
            goto error_out;
        }

        if (ret) {
            ft_mode = FT_TRANSACTION_ITER;
            vm_start();
        } else {
            ft_mode = FT_TRANSACTION_COMMIT;
            if (migrate_ft_trans_commit(s) < 0) {
                goto error_out;
            }
        }
        break;

    case FT_TRANSACTION_ITER:
        now = qemu_get_clock_ns(vm_clock);
        timeout = ((now - start) >= max_downtime);
        if (timeout || qemu_savevm_state_iterate(s->mon, s->file) == 1) {
            DPRINTF("ft trans iter timeout %d\n", timeout);

            ft_mode = FT_TRANSACTION_COMMIT;
            if (migrate_ft_trans_commit(s) < 0) {
                goto error_out;
            }
            return 1;
        }

        ft_mode = FT_TRANSACTION_ITER;
        break;

    case FT_TRANSACTION_ATOMIC:
    case FT_TRANSACTION_COMMIT:
        if (migrate_ft_trans_commit(s) < 0) {
            goto error_out;
        }
        break;

    default:
        fprintf(stderr,
                "migrate_ft_trans_put_ready: invalid ft_mode %d", ft_mode);
        goto error_out;
    }

    ret = 0;
    goto out;

error_out:
    migrate_ft_trans_error(s);

out:
    return ret;
}

static void migrate_ft_trans_connect(FdMigrationState *s, int old_vm_running)
{
    /* close buffered_file and open ft_trans_file
     * NB: fd won't get closed, and reused by ft_trans_file
     */
    qemu_fclose(s->file);

    s->file = qemu_fopen_ops_ft_trans(s,
                                      migrate_fd_put_buffer,
                                      migrate_fd_get_buffer,
                                      migrate_ft_trans_put_ready,
                                      migrate_ft_trans_get_ready,
                                      migrate_fd_wait_for_unfreeze,
                                      migrate_fd_close,
                                      1);
    socket_set_nodelay(s->fd);

    /* events are tapped from now */
    if (event_tap_register(migrate_ft_trans_put_ready) < 0) {
        migrate_ft_trans_error(s);
    }

    event_tap_schedule_suspend();

    if (old_vm_running) {
        vm_start();
    }
}

void migrate_fd_put_ready(void *opaque)
{
    FdMigrationState *s = opaque;

    if (s->state != MIG_STATE_ACTIVE) {
        DPRINTF("put_ready returning because of non-active state\n");
        return;
    }

    DPRINTF("iterate\n");
    if (qemu_savevm_state_iterate(s->mon, s->file) == 1) {
        int state;
        int old_vm_running = vm_running;

        DPRINTF("done iterating\n");
        vm_stop(VMSTOP_MIGRATE);

        if ((qemu_savevm_state_complete(s->mon, s->file)) < 0) {
            if (old_vm_running) {
                vm_start();
            }
            state = MIG_STATE_ERROR;
        } else {
            state = MIG_STATE_COMPLETED;
        }

        if (ft_mode && state == MIG_STATE_COMPLETED) {
            return migrate_ft_trans_connect(s, old_vm_running);
        }

        if (migrate_fd_cleanup(s) < 0) {
            if (old_vm_running) {
                vm_start();
            }
            state = MIG_STATE_ERROR;
        }
        s->state = state;
        notifier_list_notify(&migration_state_notifiers);
    }
}

int migrate_fd_get_status(MigrationState *mig_state)
{
    FdMigrationState *s = migrate_to_fms(mig_state);
    return s->state;
}

void migrate_fd_cancel(MigrationState *mig_state)
{
    FdMigrationState *s = migrate_to_fms(mig_state);

    if (s->state == MIG_STATE_CANCELLED) {
        return;
    }

    DPRINTF("cancelling migration\n");

    s->state = MIG_STATE_CANCELLED;
    notifier_list_notify(&migration_state_notifiers);

    if (ft_mode) {
        if (s->file) {
            qemu_ft_trans_cancel(s->file);
        }
        ft_mode = FT_OFF;
        event_tap_unregister();
    }

    if (s->file) {
        qemu_savevm_state_cancel(s->mon, s->file);
        migrate_fd_cleanup(s);
    }
}

void migrate_fd_release(MigrationState *mig_state)
{
    FdMigrationState *s = migrate_to_fms(mig_state);

    DPRINTF("releasing state\n");
   
    if (s->state == MIG_STATE_ACTIVE) {
        s->state = MIG_STATE_CANCELLED;
        notifier_list_notify(&migration_state_notifiers);
        migrate_fd_cleanup(s);
    }
    qemu_free(s);
}

void migrate_fd_wait_for_unfreeze(void *opaque)
{
    FdMigrationState *s = opaque;
    int ret;

    DPRINTF("wait for unfreeze\n");
    if (s->state != MIG_STATE_ACTIVE)
        return;

    do {
        fd_set wfds;

        FD_ZERO(&wfds);
        FD_SET(s->fd, &wfds);

        ret = select(s->fd + 1, NULL, &wfds, NULL, NULL);
    } while (ret == -1 && (s->get_error(s)) == EINTR);
}

int migrate_fd_close(void *opaque)
{
    FdMigrationState *s = opaque;

    qemu_set_fd_handler2(s->fd, NULL, NULL, NULL, NULL);
    return s->close(s);
}

void add_migration_state_change_notifier(Notifier *notify)
{
    notifier_list_add(&migration_state_notifiers, notify);
}

void remove_migration_state_change_notifier(Notifier *notify)
{
    notifier_list_remove(&migration_state_notifiers, notify);
}

int get_migration_state(void)
{
    if (current_migration) {
        return migrate_fd_get_status(current_migration);
    } else {
        return MIG_STATE_ERROR;
    }
}
