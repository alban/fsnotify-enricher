[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/fsnotify-enricher)](https://artifacthub.io/packages/search?repo=fsnotify-enricher)

# fsnotify-enricher

fsnotify-enricher is a [gadget from Inspektor
Gadget](https://inspektor-gadget.io/). It detects applications using inotify
and enriches the inotify events with the pid and process-related metadata.

## How to use

### Basic usage

```bash
$ export IG_EXPERIMENTAL=true
$ sudo -E ig run ghcr.io/alban/fsnotify-enricher:latest
```

### Example with inotify

Start an application using inotify:
```
inotifywatch /tmp/
```

You can generate events in another terminal with:
```
touch /tmp/ABCDE
```

The fsnotify-enricher gadget can observe and enrich the inotify events in the following way:
```
$ sudo -E ig run ghcr.io/alban/fsnotify-enricher:latest --verify-image=false --inotify-only --fields=tracer_comm,tracee_comm,i_wd,i_mask,i_cookie,name
INFO[0000] Experimental features enabled
WARN[0000] you set --verify-image=false, image will not be verified
WARN[0001] you set --verify-image=false, image will not be verified
TRACER_COMM  TRACEE_COMM I_WD I_MASK    I_COOKIE NAME
inotifywatch touch       1    134217760 0        ABCDE
inotifywatch touch       1    134217732 0        ABCDE
inotifywatch touch       1    134217736 0        ABCDE
```

The mask uses the same flags as inotify (`IN_ACCESS`, etc.) + some internal ones:
```
134217760 = 0x08000020 = FS_OPEN | FS_EVENT_ON_CHILD
134217732 = 0x08000004 = FS_ATTRIB | FS_EVENT_ON_CHILD
134217736 = 0x08000008 = FS_CLOSE_WRITE | FS_EVENT_ON_CHILD
```

### Example with fanotify

ig itself uses fanotify to watch containers. You can generate events in another terminal with:
```
docker run -ti --rm busybox date
```

The fsnotify-enricher gadget can observe and enrich the fanotify events in the following way:
```
$ sudo -E ig run ghcr.io/alban/fsnotify-enricher:latest --verify-image=false --fanotify-only --fields=tracer_comm,tracee_comm,group_priority,name,type_str,fa_type_str
INFO[0000] Experimental features enabled
WARN[0000] you set --verify-image=false, image will not be verified
WARN[0001] you set --verify-image=false, image will not be verified
TRACER_COMM TRACEE_COMM     GROUP_PRIORITY NAME TYPE_STR FA_TYPE_STR
ig          containerd-shim 1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          containerd-shim 1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          runc            1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          runc            1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          exe             1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          exe             1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          containerd-shim 1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
ig          containerd-shim 1                   fanotify FANOTIFY_EVENT_TYPE_PATH_PERM
```

## Parameters

You can select the applications to monitor with `--tracer-pid=` and
`--tracee-pid=`.

## Requirements

- ig v0.26.0 (TBD)
- Linux v5.15 (TBD)

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
