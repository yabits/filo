#
# Copyright (C) 2008 by coresystems GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

#include efi/core/rtlib/Makefile.inc
#include efi/core/runtime/Makefile.inc
include efi/core/x86/Makefile.inc

TARGETS-y += efi/core/acpi.o efi/core/acpitabs.o
TARGETS-y += efi/core/basepe.o efi/core/bdsboot.o
TARGETS-y += efi/core/bdscon.o efi/core/bdsentry.o
TARGETS-y += efi/core/bdsutil.o efi/core/cfgtable.o
TARGETS-y += efi/core/crc32.o
TARGETS-y += efi/core/dbgser.o efi/core/devpathu.o
TARGETS-y += efi/core/diskio.o efi/core/dispatch.o
TARGETS-y += efi/core/div.o efi/core/drvsup.o
TARGETS-y += efi/core/event.o efi/core/fatdev.o
TARGETS-y += efi/core/fatfs.o efi/core/fsvars.o
TARGETS-y += efi/core/fvblock.o efi/core/fvsect.o
TARGETS-y += efi/core/fwvol.o efi/core/fwvolio.o
TARGETS-y += efi/core/handle.o efi/core/image.o
TARGETS-y += efi/core/init.o efi/core/intr.o
TARGETS-y += efi/core/locate.o efi/core/lock.o
TARGETS-y += efi/core/memory.o efi/core/part.o
TARGETS-y += efi/core/partelto.o efi/core/partgpt.o
TARGETS-y += efi/core/partmbr.o efi/core/pool.o
TARGETS-y += efi/core/ramdisk.o efi/core/smbios.o
TARGETS-y += efi/core/stubs.o efi/core/tpl.o
TARGETS-y += efi/core/timer.o efi/core/util.o
TARGETS-y += efi/core/version.o efi/core/vidcon.o

