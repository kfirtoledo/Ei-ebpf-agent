# EI eBPF Agent

The EI eBPF Agent allows collecting and aggregating all the ingress and
egress flows on a Linux host (required a Kernel 4.18+ with eBPF enabled).

* [How to compile](#how-to-compile)
* [Hot to configure](#how-to-configure)
* [How to run](#how-to-run)
* [Development receipts](#development-receipts)

## How to compile

```
make build
```

To build the agent image and push it to your Docker / Quay repository, run:

```bash
IMG=quay.io/myaccount/ei-ebpf-agent:dev make image-build image-push
```

## How to configure

The eBPF Agent is configured by means of environment variables. Check the
[configuration documentation](./docs/config.md) for more details.

## How to run

```
sudo -E bin/ei-ebpf-agent
```

To deploy it as a Pod, you can check the [deployment examples](./examples/ei-agent).

The Agent needs to be executed either with:

1. The following [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
   (recommended way): `BPF`, `PERFMON`, `NET_ADMIN`, `SYS_RESOURCE`. If you
   [deploy it in Kubernetes or OpenShift](./deployments/flp-daemonset-cap.yml),
   the container running the Agent needs to define the following `securityContext`:
   ```yaml
   securityContext:
     runAsUser: 0
     capabilities:
       add:
         - BPF
         - PERFMON
         - NET_ADMIN
         - SYS_RESOURCE
   ```
   (Please notice that the `runAsUser: 0` is still needed).
2. Administrative privileges. If you
   [deploy it in Kubernetes or OpenShift](./deployments/flp-daemonset.yml),
   the container running the Agent needs to define the following `securityContext`:
   ```yaml
   securityContext:
     privileged: true
     runAsUser: 0
   ```
   This option is only recommended if your Kernel does not recognize some of the above capabilities.
   We found some Kubernetes distributions (e.g. K3s) that do not recognize the `BPF` and
   `PERFMON` capabilities.

Here is a list of distributions where we tested both full privileges and capability approaches,
and whether they worked (✅) or did not (❌):

| Distribution                  | K8s Server version | Capabilities | Privileged |
|-------------------------------|--------------------|--------------|------------|
| Amazon EKS (Bottlerocket AMI) | 1.22.6             | ✅            | ✅          |
| K3s (Rancher Desktop)         | 1.23.5             | ❌            | ✅          |
| Kind                          | 1.23.5             | ❌            | ✅          |
| OpenShift                     | 1.23.3             | ✅            | ✅          |


## Development receipts

### How to regenerate the eBPF Kernel binaries

The eBPF program is embedded into the `pkg/ebpf/bpf_*` generated files.
This step is generally not needed unless you change the C code in the `bpf` folder.

If you have Docker installed, you just need to run:

```
make docker-generate
```

If you can't install docker, you should locally install the following required packages:

```
dnf install -y kernel-devel make llvm clang glibc-devel.i686
make generate
```

Tested in Fedora 35 and Red Hat Enterprise Linux 8.
