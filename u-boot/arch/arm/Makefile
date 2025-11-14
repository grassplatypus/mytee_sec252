# SPDX-License-Identifier: GPL-2.0+

ifeq ($(CONFIG_SPL_BUILD)$(CONFIG_TEGRA),yy)
CONFIG_CPU_V7A=
CONFIG_CPU_ARM720T=y
endif

# This selects which instruction set is used.
arch-$(CONFIG_CPU_V7A)		=$(call cc-option, -march=armv7-a, \
				 $(call cc-option, -march=armv7))
arch-$(CONFIG_CPU_V7M)		=-march=armv7-m
arch-$(CONFIG_CPU_V7R)		=-march=armv7-r
arch-$(CONFIG_ARM64)		=-march=armv8-a

# On Tegra systems we must build SPL for the armv4 core on the device
# but otherwise we can use the value in CONFIG_SYS_ARM_ARCH
ifeq ($(CONFIG_SPL_BUILD)$(CONFIG_TEGRA),yy)
arch-y += -D__LINUX_ARM_ARCH__=4
else
arch-y += -D__LINUX_ARM_ARCH__=$(CONFIG_SYS_ARM_ARCH)
endif

# Evaluate arch cc-option calls now
arch-y := $(arch-y)

# This selects how we optimise for the processor.
tune-$(CONFIG_CPU_V7A)		=-mtune=generic-armv7-a
tune-$(CONFIG_CPU_V7R)		=
tune-$(CONFIG_ARM64)		=

# Evaluate tune cc-option calls now
tune-y := $(tune-y)

PLATFORM_CPPFLAGS += $(arch-y) $(tune-y)

# Machine directory name.  This list is sorted alphanumerically
# by CONFIG_* macro name.
machine-$(CONFIG_ARCH_BCM283X)		+= bcm283x


machdirs := $(patsubst %,arch/arm/mach-%/,$(machine-y))

PLATFORM_CPPFLAGS += $(patsubst %,-I$(srctree)/%include,$(machdirs))

libs-y += $(machdirs)

head-y := arch/arm/cpu/$(CPU)/start.o

ifeq ($(CONFIG_SPL_BUILD),y)
ifneq ($(CONFIG_SPL_START_S_PATH),)
head-y := $(CONFIG_SPL_START_S_PATH:"%"=%)/start.o
endif
endif

libs-y += arch/arm/cpu/$(CPU)/
libs-y += arch/arm/cpu/
libs-y += arch/arm/lib/

ifeq ($(CONFIG_SPL_BUILD),y)
ifneq (,$(CONFIG_MX23)$(CONFIG_MX28)$(CONFIG_MX35)$(filter $(SOC), mx25 mx5 mx6 mx7 mx35 mx8m))
libs-y += arch/arm/mach-imx/
endif
else
ifneq (,$(filter $(SOC), mx25 mx27 mx5 mx6 mx7 mx7ulp mx31 mx35 mxs mx8m imx8 vf610))
libs-y += arch/arm/mach-imx/
endif
endif

ifneq (,$(filter $(SOC), kirkwood))
libs-y += arch/arm/mach-mvebu/
endif

# deprecated
-include $(machdirs)/config.mk
