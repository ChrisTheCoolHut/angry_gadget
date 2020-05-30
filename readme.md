# Angry Gadget

Locating OneGadgets in libc.

Inspired by [OneGadget](https://github.com/david942j/one_gadget) this tool is written in python and uses [angr](https://github.com/angr/angr) to test constraints for gadgets executing `execve('/bin/sh', NULL, NULL)`

If you've run out gadgets to try from OneGadget, Angry Gadget gives a lot more with complicated constraints to try!

# Installation
```
pip install angry_gadget
```
or
```
git clone https://github.com/ChrisTheCoolHut/angry_gadget.git
cd angry_gadget
pip install -e .
```

# Usage

The python script accepts one positional argument.

```
$ angry_gadget.py -h
usage: angry_gadget.py [-h] binary

positional arguments:
  binary

optional arguments:
  -h, --help  show this help message and exit
```

# Example 

```
$ angry_gadget.py examples/libc6_2.23-0ubuntu10_amd64.so 
Building CFG, this will take a moment
100% |###############################################################################################| Elapsed Time: 0:03:08 Time:  0:03:08
Iterating over XREFs looking for gadget
100%|#######################################################################################################| 14/14 [00:01<00:00,  8.39it/s]
Trying 0x4f0fe9: 100%|######################################################################################| 16/16 [02:03<00:00,  7.75s/it]
libc_base + 0xf6661 :
	<Bool reg_rbx_114460_64{UNINITIALIZED}[60:0] == 0x1fffffffffffffff>
	<Bool !(reg_cc_dep1_114463_64{UNINITIALIZED}[6:6] == 0)>
	<Bool reg_rbp_114471_64{UNINITIALIZED} == 0xf6>
	<Bool True>
	<Bool reg_rcx_114473_64{UNINITIALIZED} <= 0xffffffffffffffff>
	<Bool reg_rcx_114473_64{UNINITIALIZED} == 0xfffffffffff80000>
libc_base + 0xf6669 :
	<Bool reg_rbx_114476_64{UNINITIALIZED}[60:0] == 0x1ffffffffffffffe>
	<Bool !(reg_cc_dep1_114478_64{UNINITIALIZED}[6:6] == 0)>
	<Bool reg_rbp_114486_64{UNINITIALIZED} == 0xf4>
	<Bool True>
	<Bool reg_rcx_114488_64{UNINITIALIZED} <= 0xffffffffffffffff>
	<Bool reg_rcx_114488_64{UNINITIALIZED} == 0x8000000000000000>
 ----- SNIP ------
libc_base + 0xf115d :
	<Bool True>
	<Bool reg_rsi_114729_64{UNINITIALIZED} <= 0xffffffffffffffff>
	<Bool reg_rsi_114729_64{UNINITIALIZED} == 0xffffffffffffffc0>
libc_base + 0x6f5bb :
	<Bool reg_rsi_114534_64{UNINITIALIZED} == 0x0>
libc_base + 0x6f5be :
	<Bool reg_rsi_114544_64{UNINITIALIZED} == 0x0>
libc_base + 0x6f5c1 :
	<Bool reg_rsi_114555_64{UNINITIALIZED} == 0x0>
libc_base + 0x6f5c3 :
	<Bool reg_rsi_114567_64{UNINITIALIZED} == 0x0>
libc_base + 0x4526a :
libc_base + 0xf02a4 :
libc_base + 0xf1147 :
```

# Notes

 * It's slower than OneGadget, so you should probably still use that.
 * It's only 64bit, if there is interest, I can expand it to 32bit.
