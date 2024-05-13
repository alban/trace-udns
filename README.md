# trace-udns

trace-udns is a [gadget from Inspektor Gadget](https://inspektor-gadget.io/).
It detects DNS requests using uprobes.

## How to use

```bash
$ export IG_EXPERIMENTAL=true
$ sudo -E ig run ghcr.io/alban/trace-udns:latest
```

## Requirements

- ig v0.28.0
- Linux v5.15 (TBD)

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
