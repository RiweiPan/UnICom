
**Note**: Please try UnICom (namely Nap in the source code) on Ubuntu 20.04 with GCC 9 and an Intel Optane P5801x SSD.
**Quick Start**: 
1. Run `utils/build_linux_kernel.sh` to build and install the Linux kernel, then reboot the system.
2. Run `utils/build_mix_iostester.sh` to build the micro-benchmark tool.
3. Run `ae/run_exp_once.bash` to run experiments. You can change the input arguments to run different configurations. Please refer to `ae/micro-io/run_motiv_exp_4k.bash` for an example.
