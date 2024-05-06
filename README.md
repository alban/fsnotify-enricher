# fsnotify-enricher

fsnotify-enricher is a [gadget from Inspektor
Gadget](https://inspektor-gadget.io/). It detects applications using inotify
and enriches the inotify events with the pid and process-related metadata.

## How to use

```bash
$ export IG_EXPERIMENTAL=true
$ sudo -E ig run ghcr.io/alban/fsnotify-enricher:latest
```

Start an application using inotify:
```
inotifywatch /tmp/
```

You can generate events in another terminal with:
```
touch /tmp/abcde
```

The fsnotify-enricher gadget can observe and enrich the inotify events in the following way:
```
$ sudo IG_EXPERIMENTAL=true ig run ghcr.io/alban/fsnotify-enricher:bf6803d-dirty --verify-image=false --fields=type_str,tracer_pid,tracer_comm,tracee_pid,tracee_comm,i_mask,name
INFO[0000] Experimental features enabled
WARN[0000] you set --verify-image=false, image will not be verified
WARN[0002] you set --verify-image=false, image will not be verified
TYPE_STR                                 TRACER_PID                TRACER_COMM                              TRACEE_PID                TRACEE_COMM                             I_MASK                   NAME
inotify                                  2496541                   inotifywatch                             2510588                   touch                                   134217760                abcd
inotify                                  2496541                   inotifywatch                             2510588                   touch                                   134217732                abcd
inotify                                  2496541                   inotifywatch                             2510588                   touch                                   134217736                abcd
```

You can select the applications to monitor with `--tracer-pid=` and
`--tracee-pid=`.

The mask uses the same flags as inotify (`IN_ACCESS`, etc.) + some internal ones:
```
134217760 = 0x08000020 = FS_OPEN | FS_EVENT_ON_CHILD
134217732 = 0x08000004 = FS_ATTRIB | FS_EVENT_ON_CHILD
134217736 = 0x08000008 = FS_CLOSE_WRITE | FS_EVENT_ON_CHILD
```

## Requirements

- ig v0.26.0 (TBD)
- Linux v5.15 (TBD)

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
