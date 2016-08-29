// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ring.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include <ddk/driver.h>
#include <magenta/syscalls.h>

#include "device.h"
#include "trace.h"

#define LOCAL_TRACE 0

namespace virtio {

void virtio_dump_desc(const struct vring_desc* desc) {
    printf("vring descriptor %p: ", desc);
    printf(" addr  %#llx", desc->addr);
    printf(" len   %#8x", desc->len);
    printf(" flags %#02hhx", desc->flags);
    printf(" next  %#02hhx\n", desc->next);
}

Ring::Ring(Device* device)
    : device_(device) {}

Ring::~Ring() {
    // TOOD: clean up allocated memory
}

mx_status_t Ring::Init(uint16_t index, uint16_t count) {
    LTRACEF("index %u, count %u\n", index, count);

    // XXX check that count is a power of 2

    index_ = index;

    // allocate a ring
    size_t size = vring_size(count, PAGE_SIZE);
    LTRACEF("need %zu bytes\n", size);

    mx_status_t r = mx_alloc_device_memory(get_root_resource(), (uint32_t)size, &ring_pa_, &ring_ptr_);
    if (r < 0) {
        TRACEF("cannot alloc buffers %d\n", r);
        return r;
    }

    LTRACEF("allocated vring at %p, physical address 0x%lx\n", ring_ptr_, ring_pa_);

    /* initialize the ring */
    vring_init(&ring_, count, ring_ptr_, PAGE_SIZE);
    ring_.free_list = 0xffff;
    ring_.free_count = 0;

    /* add all the descriptors to the free list */
    for (uint16_t i = 0; i < count; i++) {
        FreeDesc(i);
    }

    /* register the ring with the device */
    mx_paddr_t pa_desc = ring_pa_;
    mx_paddr_t pa_avail = ring_pa_ + ((uintptr_t)ring_.avail - (uintptr_t)ring_.desc);
    mx_paddr_t pa_used = ring_pa_ + ((uintptr_t)ring_.used - (uintptr_t)ring_.desc);
    device_->SetRing(index_, count, pa_desc, pa_avail, pa_used);

#if 0
    /* mark the ring active */
    dev->active_rings_bitmap |= (1 << index_);
#endif

    return NO_ERROR;
}

void Ring::FreeDesc(uint16_t desc_index) {
    LTRACEF("index %u free_count %u\n", desc_index, ring_.free_count);
    ring_.desc[desc_index].next = ring_.free_list;
    ring_.free_list = desc_index;
    ring_.free_count++;
}

void Ring::FreeDescChain(uint16_t chain_head) {
    struct vring_desc* desc = &ring_.desc[chain_head];

    while (desc->flags & VRING_DESC_F_NEXT) {
        uint16_t next = desc->next;
        FreeDesc(chain_head);
        chain_head = next;
        desc = &ring_.desc[chain_head];
    }

    FreeDesc(chain_head);
}

uint16_t Ring::AllocDesc() {
    if (ring_.free_count == 0)
        return 0xffff;

    assert(ring_.free_list != 0xffff);

    uint16_t i = ring_.free_list;
    struct vring_desc* desc = &ring_.desc[i];
    ring_.free_list = desc->next;

    ring_.free_count--;

    return i;
}

struct vring_desc* Ring::AllocDescChain(uint16_t count, uint16_t* start_index) {
    if (ring_.free_count < count)
        return NULL;

    /* start popping entries off the chain */
    struct vring_desc* last = 0;
    uint16_t last_index = 0;
    while (count > 0) {
        uint16_t i = ring_.free_list;
        struct vring_desc* desc = &ring_.desc[i];

        ring_.free_list = desc->next;
        ring_.free_count--;

        if (last) {
            desc->flags = VRING_DESC_F_NEXT;
            desc->next = last_index;
        } else {
            // first one
            desc->flags = 0;
            desc->next = 0;
        }
        last = desc;
        last_index = i;
        count--;
    }

    if (start_index)
        *start_index = last_index;

    return last;
}

void Ring::SubmitChain(uint16_t desc_index) {
    LTRACEF("desc %u\n", desc_index);

    /* add the chain to the available list */
    struct vring_avail* avail = ring_.avail;

    avail->ring[avail->idx & ring_.num_mask] = desc_index;
    //mb();
    avail->idx++;
}

void Ring::Kick() {
    LTRACE_ENTRY;

    device_->RingKick(index_);
}

#if 0
status_t virtio_alloc_ring(struct virtio_device *dev, uint index, uint16_t len)
{
    LTRACEF("dev %p, index %u, len %u\n", dev, index, len);

    DEBUG_ASSERT(dev);
    DEBUG_ASSERT(len > 0 && ispow2(len));
    DEBUG_ASSERT(index < MAX_VIRTIO_RINGS);

    if (len == 0 || !ispow2(len))
        return ERR_INVALID_ARGS;

    struct vring *ring = &dev->ring[index];

    /* allocate a ring */
    size_t size = vring_size(len, PAGE_SIZE);
    LTRACEF("need %zu bytes\n", size);

#if WITH_KERNEL_VM
    void *vptr;
    status_t err = vmm_alloc_contiguous(vmm_get_kernel_aspace(), "virtio_ring", size, &vptr,
            0, VMM_FLAG_COMMIT, ARCH_MMU_FLAG_UNCACHED_DEVICE);
    if (err < 0)
        return ERR_NO_MEMORY;

    LTRACEF("allocated virtio_ring at va %p\n", vptr);

    /* compute the physical address */
    paddr_t pa;
    pa = vaddr_to_paddr(vptr);
    if (pa == 0) {
        return ERR_NO_MEMORY;
    }

    LTRACEF("virtio_ring at pa 0x%lx\n", pa);
#else
    void *vptr = memalign(PAGE_SIZE, size);
    if (!vptr)
        return ERR_NO_MEMORY;

    LTRACEF("ptr %p\n", vptr);
    memset(vptr, 0, size);

    /* compute the physical address */
    paddr_t pa = (paddr_t)vptr;
#endif

    /* initialize the ring */
    vring_init(ring, len, vptr, PAGE_SIZE);
    dev->ring[index].free_list = 0xffff;
    dev->ring[index].free_count = 0;

    /* add all the descriptors to the free list */
    for (uint i = 0; i < len; i++) {
        virtio_free_desc(dev, index, i);
    }

    /* register the ring with the device */
    if (dev->type == VIO_MMIO) {
        dev->mmio.mmio_config->guest_page_size = PAGE_SIZE;
        dev->mmio.mmio_config->queue_sel = index;
        dev->mmio.mmio_config->queue_num = len;
        dev->mmio.mmio_config->queue_align = PAGE_SIZE;
        dev->mmio.mmio_config->queue_pfn = pa / PAGE_SIZE;
#if WITH_DEV_PCIE
    } else if (dev->type == VIO_PCI) {
        pcie_io_write16(dev->pci.pci_control_bar, VIRTIO_PCI_QUEUE_SELECT, index);
        pcie_io_write16(dev->pci.pci_control_bar, VIRTIO_PCI_QUEUE_SIZE, len);
        pcie_io_write32(dev->pci.pci_control_bar, VIRTIO_PCI_QUEUE_PFN, pa / PAGE_SIZE);
#endif
    }

    /* mark the ring active */
    dev->active_rings_bitmap |= (1 << index);

    return NO_ERROR;
}
#endif

} // namespace virtio
