// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

#define PATH_MAX 4096
#define TASK_COMM_LEN 16

enum type {
  unknown,
  dnotify,
  inotify,
  fanotify,
};

struct enriched_event {
  enum type type;

  __u32 pid;
  __u32 tid;
  __u8 comm[TASK_COMM_LEN];
  gadget_mntns_id mntns_id;

  __u32 group_priority;

  __u32 fa_type;
  __u32 fa_mask;
  __u32 fa_pid;
  __u32 fa_flags;
  __u32 fa_f_flags;

  __s32 i_wd;
  __u32 i_mask;
  __u32 i_cookie;

  __u8 name[PATH_MAX];
};
static const struct enriched_event empty_enriched_event = {};

// context for the caller of fsnotify_insert_event
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, u64); // tgid_pid
  __type(value, enum type);
} fsnotify_insert_event_ctx SEC(".maps");

// context for kprobe/kretprobe fsnotify_remove_first_event
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, u64);      // tgid_pid
  __type(value, void *); // struct fsnotify_group *
} fsnotify_remove_first_event_ctx SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, void *); // struct fsnotify_event *event
  __type(value, struct enriched_event);
  __uint(max_entries, 10240);
} enriched_fsnotify_events SEC(".maps");

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

const volatile u64 tracer_group = 0;
const volatile pid_t tracer_pid = 0;
const volatile pid_t tracee_pid = 0;
const volatile bool inotify_only = false;
const volatile bool fanotify_only = false;
GADGET_PARAM(tracer_group);
GADGET_PARAM(tracer_pid);
GADGET_PARAM(tracee_pid);
GADGET_PARAM(inotify_only);
GADGET_PARAM(fanotify_only);

struct event {
  gadget_timestamp timestamp;
  enum type type;

  gadget_mntns_id mntns_id;
  __u32 tracer_pid;
  __u32 tracer_tid;
  char tracer_comm[TASK_COMM_LEN];

  gadget_mntns_id tracee_mntns_id;
  __u32 tracee_pid;
  __u32 tracee_tid;
  char tracee_comm[TASK_COMM_LEN];

  __u32 group_priority;

  enum fanotify_event_type fa_type;
  __u32 fa_mask;
  __u32 fa_pid;
  __u32 fa_flags;
  __u32 fa_f_flags;

  __s32 i_wd;
  __u32 i_mask;
  __u32 i_cookie;

  char name[PATH_MAX];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(fsnotify, events, event);

// Probes for the tracees

SEC("kprobe/inotify_handle_inode_event")
int BPF_KPROBE(inotify_handle_inode_event_e) {
  if (!fanotify_only) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    enum type type = inotify;
    // context for fsnotify_insert_event
    bpf_map_update_elem(&fsnotify_insert_event_ctx, &pid_tgid, &type, 0);
  }
  return 0;
}

SEC("kretprobe/inotify_handle_inode_event")
int BPF_KRETPROBE(inotify_handle_inode_event_x, int ret) {
  if (!fanotify_only) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&fsnotify_insert_event_ctx, &pid_tgid);
  }
  return 0;
}

SEC("kprobe/fanotify_handle_event")
int BPF_KPROBE(fanotify_handle_event_e) {
  if (!inotify_only) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    enum type type = fanotify;
    // context for fsnotify_insert_event
    bpf_map_update_elem(&fsnotify_insert_event_ctx, &pid_tgid, &type, 0);
  }
  return 0;
}

SEC("kretprobe/fanotify_handle_event")
int BPF_KRETPROBE(fanotify_handle_event_x, int ret) {
  if (!inotify_only) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&fsnotify_insert_event_ctx, &pid_tgid);
  }
  return 0;
}

SEC("kprobe/fsnotify_insert_event")
int BPF_KPROBE(fsnotify_insert_event_e, struct fsnotify_group *group,
               struct fsnotify_event *event) {
  u64 pid_tgid;
  struct enriched_event *ee;
  enum type *type;
  struct fanotify_event *fae;
  struct inotify_event_info *ine;
  int name_len;
  struct path *p = NULL;

  pid_tgid = bpf_get_current_pid_tgid();

  if (tracee_pid && tracee_pid != pid_tgid >> 32)
    return 0;

  type = bpf_map_lookup_elem(&fsnotify_insert_event_ctx, &pid_tgid);
  if (type) {
    if (inotify_only && *type != inotify)
      return 0;
    if (fanotify_only && *type != fanotify)
      return 0;
  } else {
    if (inotify_only || fanotify_only)
      return 0;
  }

  bpf_map_update_elem(&enriched_fsnotify_events, &event, &empty_enriched_event,
                      BPF_NOEXIST);
  ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
  if (!ee)
    return 0;

  ee->pid = pid_tgid >> 32;
  ee->tid = (u32)pid_tgid;
  bpf_get_current_comm(&ee->comm, sizeof(ee->comm));
  ee->mntns_id = gadget_get_mntns_id();

  ee->group_priority = BPF_CORE_READ(group, priority);

  if (type) {
    ee->type = *type;

    ee->fa_type = -1;

    switch (ee->type) {
    case inotify:
      ine = container_of(event, struct inotify_event_info, fse);
      ee->i_wd = BPF_CORE_READ(ine, wd);
      ee->i_mask = BPF_CORE_READ(ine, mask);
      ee->i_cookie = BPF_CORE_READ(ine, sync_cookie);

      name_len = BPF_CORE_READ(ine, name_len);
      if (name_len < 0)
        name_len = 0;
      name_len++; // ine->name_len does not include the NULL at the end
      if (name_len > PATH_MAX)
        name_len = PATH_MAX;
      bpf_probe_read_kernel_str(&ee->name, name_len, &ine->name[0]);
      break;

    case fanotify:
      fae = container_of(event, struct fanotify_event, fse);
      ee->fa_mask = BPF_CORE_READ(fae, mask);
      ee->fa_type = BPF_CORE_READ_BITFIELD_PROBED(fae, type);
      ee->fa_pid = BPF_CORE_READ(fae, pid, numbers[0].nr);
      ee->fa_flags = BPF_CORE_READ(group, fanotify_data.flags);
      ee->fa_f_flags = BPF_CORE_READ(group, fanotify_data.f_flags);

      if (ee->fa_type == FANOTIFY_EVENT_TYPE_PATH)
        p = &container_of(fae, struct fanotify_path_event, fae)->path;
      else if (ee->fa_type == FANOTIFY_EVENT_TYPE_PATH_PERM)
        p = &container_of(fae, struct fanotify_perm_event, fae)->path;

      if (p)
        bpf_probe_read_kernel_str(ee->name, PATH_MAX, get_path_str(p));

      break;

    default:
      break;
    }
  }

  // fsnotify_insert_event() might not add the event, but
  // fsnotify_destroy_event() will be called in any cases.
  bpf_map_update_elem(&enriched_fsnotify_events, &event, ee, 0);

  return 0;
}

SEC("kprobe/fsnotify_destroy_event")
int BPF_KPROBE(fsnotify_destroy_event, struct fsnotify_group *group,
               struct fsnotify_event *event) {
  // This might be called for unrelated events. This is fine:
  // bpf_map_delete_elem would just ignore events that are not in the
  // map.
  bpf_map_delete_elem(&enriched_fsnotify_events, &event);
  return 0;
}

// Probes for the tracers

SEC("kprobe/fsnotify_remove_first_event")
int BPF_KPROBE(ig_fa_pick_e, struct fsnotify_group *group) {
  u64 pid_tgid;

  pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  if (tracer_pid && tracer_pid != tgid)
    return 0;

  if (tracer_group && tracer_group != (u64)group)
    return 0;

  // context for kretprobe
  bpf_map_update_elem(&fsnotify_remove_first_event_ctx, &pid_tgid, &group, 0);

  return 0;
}

SEC("kretprobe/fsnotify_remove_first_event")
int BPF_KRETPROBE(ig_fa_pick_x, struct fsnotify_event *ret) {
  u64 pid_tgid;
  struct fsnotify_group **group;
  struct enriched_event *ee;
  struct event *event;

  // pid_tgid is the task owning the fsnotify fd
  pid_tgid = bpf_get_current_pid_tgid();

  group = bpf_map_lookup_elem(&fsnotify_remove_first_event_ctx, &pid_tgid);
  if (!group)
    return 0;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    goto end;

  /* event data */
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_mntns_id();
  event->tracer_pid = pid_tgid >> 32;
  event->tracer_tid = (u32)pid_tgid;
  bpf_get_current_comm(&event->tracer_comm, sizeof(event->tracer_comm));

  ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &ret);
  if (ee) {
    event->type = ee->type;
    event->tracee_pid = ee->pid;
    event->tracee_tid = ee->tid;
    __builtin_memcpy(event->tracee_comm, ee->comm, TASK_COMM_LEN);
    event->tracee_mntns_id = ee->mntns_id;
    event->group_priority = ee->group_priority;

    event->fa_type = ee->fa_type;
    event->fa_mask = ee->fa_mask;
    event->fa_pid = ee->fa_pid;
    event->fa_flags = ee->fa_flags;
    event->fa_f_flags = ee->fa_f_flags;

    event->i_wd = ee->i_wd;
    event->i_mask = ee->i_mask;
    event->i_cookie = ee->i_cookie;

    bpf_probe_read_kernel_str(event->name, PATH_MAX, ee->name);
  } else {
    if (inotify_only || fanotify_only) {
      gadget_discard_buf(event);
      goto end;
    }
  }

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

end:
  bpf_map_delete_elem(&fsnotify_remove_first_event_ctx, &pid_tgid);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
