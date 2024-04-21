MODULE_NAME = hack
$(MODULE_NAME)-objs := hello.o
obj-m := $(MODULE_NAME).o

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-misleading-indentation -Wno-incompatible-pointer-types
ccflags-y += -Wno-macro-redefined -Wno-declaration-after-statement -Os

