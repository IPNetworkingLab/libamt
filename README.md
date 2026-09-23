# libamt

A small, standalone C library implementing the gateway side of Automatic
Multicast Tunneling (AMT, RFC 7450). See [amt.md](amt.md) for the full
write-up (protocol walkthrough, wire format, API summary, scope and
limitations) and [amt.h](amt.h) for the API doc comments.

Originally developed inside [dbeacon](https://github.com/venaas/dbeacon)
(see `-amt` support there), and split out here so it can be reused as a
library by other callers.

## Build

```
make            # builds libamt.a
```

## Test

`tests/run_netns_test.sh` exercises the library end-to-end across a real
veth link between two Linux network namespaces (one as gateway, one as a
mock AMT relay). Linux-only, needs root:

```
make test-amt-netns
```

## License

MIT — see [LICENSE](LICENSE).
