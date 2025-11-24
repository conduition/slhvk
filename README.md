# slhvk

SLH-DSA (SPHINCS+) using Vulkan Compute Shaders for Maximum Speeeed.

### For context, read [my survey of SLH-DSA optimization techniques](https://conduition.io/code/fast-slh-dsa/).

## Vulkanized SLH-DSA

This library is a fusion of two technologies:

- [SLH-DSA](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf): the post-quantum hash-based cryptographic signature algorithm
- [Vulkan](https://www.vulkan.org/): an open and modern graphics programming standard

This library accelerates SLH-DSA signing, keygen, and verification operations by using [Vulkan compute shaders](https://vulkan-tutorial.com/Compute_Shader) to make maximal use of available CPU and/or GPU resources. The speedup for signing and keygen especially is beyond what would otherwise be possible using standard CPU code alone. This is most effective for SLH-DSA signing and keygen because these operations are inherently highly parallel, whereas verification is not.

I have also implemented a verification shader which can effectively parallelize verification of large batches of signatures, albeit at the expense of lower performance when verifying smaller batches of signatures.

### Signing Diagram

The signing shaders can be load balanced across two Vulkan devices, with most work executing in parallel.

![slhvk-signing-flow](https://github.com/user-attachments/assets/3b2d8b97-199d-4d87-86d2-6ec13716388d)

Note this is only effective if the primary device would otherwise be overwhelmed. If you have a powerful enough GPU, it may actually be better to let that one GPU do all the work, rather than entrust some of it to a less powerful device.

## Status

This code is intended for research and experimentation. While it passes all applicable NIST test vectors, this library is not yet ready for production use and may be vulnerable to unknown security vulnerabilities.

Currently I have only implemented the `SLH-DSA-SHA2-128s` parameter set, though theoretically `SLH-DSA-SHA2-128f` could be supported by changing a few constants. The higher-security parameter sets, and the SHA3 parameter sets, are not yet supported.

## Contributing

> [!warning]
> I wrote this library on a Linux machine. As I do not have a mac or windows machine to test on, it may not be fully cross-platform. If you are a developer who can help expand this project to support other platforms, please [open an issue so we can discuss!](https://github.com/conduition/slhvk/issues/new)

To build `slhvk` code, you will need:

- A C compiler
- A GLSL compiler: `glslangValidator` or `glslc`
- `libvulkan-dev`
- `make`

This library contains a set of [unit tests](https://github.com/conduition/slhvk/tree/main/tests/bin/unit) which validate against [the NIST ACVP server test vectors](https://github.com/usnistgov/ACVP-Server/), and a set of [benchmarks](https://github.com/conduition/slhvk/tree/main/tests/bin/bench) to evaluate the performance of the signing, keygen, and verification algorithms.

To run `slhvk` tests and benchmarks, you need a Vulkan loader and driver. Most systems should have this by default if `libvulkan` is installed. If in doubt, install the [Vulkan SDK](https://vulkan.lunarg.com/sdk/home) which should include everything you need to run `slhvk` shaders on your CPU.

To run `slhvk` on your GPU, you may need to install vendor-specific drivers for your graphics card. I'll leave these here:

- https://www.nvidia.com/en-us/drivers/
- https://www.amd.com/en/support/download/drivers.html
- https://www.intel.com/content/www/us/en/download-center/home.html

I highly recommend installing `vulkaninfo` so you can easily see which devices are recognized by Vulkan (try `vulkaninfo --summary`). `vulkaninfo` is included in the Vulkan SDK, or see the `vulkan-tools` package on ubuntu/debian.

### Linux Dependency Oneliner

```sh
sudo apt install -y build-essential libvulkan-dev glslang-tools vulkan-tools
```

### Building

To build `slhvk` as a static library in `lib/libslhvk.a`:

```sh
make
```

### Header

The exported public API of `libslhvk` is declared in [the `include/slhvk.h` header file](./include/slhvk.h)

### Unit Tests

To confirm `slhvk` is working correctly, generating valid signatures, etc:

```sh
make unit
```

On first-run this will download NIST test vectors from Github. Once downloaded, the tests will run in sequence. Afterwards you should see output like this:

```
RUN acvp_keygen.test
computed 10 pk roots in 20.52 ms
  OK

RUN acvp_verify.test
verified 14 test cases in 10.22 ms
  OK

RUN acvp_sign.test
computed 14 valid signatures in 176.25 ms
  OK
```

### Benchmarks

To evaluate the runtime performance of `slhvk` on your device:

```sh
make bench
```

You should see output like this:

```
RUN bench_verify.test
initialized SLHVK context in 4757.13 ms
took 15071 ns per sig verification
  OK

RUN bench_sign.test
initialized SLHVK context in 4659.92 ms
took 12.14 ms per signature
took 10.32 ms per signature (cached root tree)
  OK

RUN bench_keygen.test
initialized SLHVK context in 4761.44 ms
took 1.03 ms per key gen
  OK
```

## Device Control

Vulkan programs have control over individual hardware processing devices, like CPUs or GPUs, and can assign workloads to different devices independently. `slhvk` can use up to two devices to generate signatures, spreading the work out for efficiency. The "primary" device is used for the bulk of the work in signing, as well as for keygen and verification. The "secondary" device is used for a smaller parallel subtask within the signing algorithm (FORS).

If only one Vulkan device is available, `slhvk` will use that device as both the "primary" and "secondary" device. If more than one device is available, `slhvk` will sort devices by the amount of shared compute memory they have, and automatically select the top two as the primary and secondary devices.

This is a temporary situation - eventually I'd like the caller to be have more control in selecting which devices are used. For now this tends to effectively detect the best primary device automatically.

If you'd like to force `slhvk` to use only CPU devices, simply set `SLHVK_FORCE_CPU=1` in your environment at runtime. E.g. to test SLHVK using only your CPU:

```sh
SLHVK_FORCE_CPU=1 make unit
```

Similarly to force `slhvk` to use only GPU devices:

```sh
SLHVK_FORCE_GPU=1 make unit
```

If you set both, `slhvk` will return errors.
