// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "block.h"

#include <hexdump/hexdump.h>
#include <magenta/compiler.h>
#include <ddk/protocol/block.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/param.h>

#include "autolock.h"
#include "trace.h"

#define LOCAL_TRACE 0

// clang-format off
#define VIRTIO_BLK_F_BARRIER  (1<<0)
#define VIRTIO_BLK_F_SIZE_MAX (1<<1)
#define VIRTIO_BLK_F_SEG_MAX  (1<<2)
#define VIRTIO_BLK_F_GEOMETRY (1<<4)
#define VIRTIO_BLK_F_RO       (1<<5)
#define VIRTIO_BLK_F_BLK_SIZE (1<<6)
#define VIRTIO_BLK_F_SCSI     (1<<7)
#define VIRTIO_BLK_F_FLUSH    (1<<9)
#define VIRTIO_BLK_F_TOPOLOGY (1<<10)
#define VIRTIO_BLK_F_CONFIG_WCE (1<<11)

#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1
#define VIRTIO_BLK_T_FLUSH      4

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2
// clang-format on

namespace virtio {

// DDK level ops

// queue an iotxn. iotxn's are always completed by its complete() op
void BlockDevice::virtio_block_iotxn_queue(mx_device_t* dev, iotxn_t* txn) {
    LTRACEF("dev %p, txn %p\n", dev, txn);

    // TODO: get a void * in the device structure so we dont need to do this
    Device* d = Device::MXDeviceToObj(dev);
    BlockDevice* bd = static_cast<BlockDevice*>(d);

    (void)bd;

    switch (txn->opcode) {
    case IOTXN_OP_READ: {
        LTRACEF("READ offset %#llx length %#llx\n", txn->offset, txn->length);
        bd->QueueReadWriteTxn(txn);
        break;
    }
    case IOTXN_OP_WRITE:
        LTRACEF("WRITE offset %#llx length %#llx\n", txn->offset, txn->length);
        bd->QueueReadWriteTxn(txn);
        break;
    default:
        txn->ops->complete(txn, -1, 0);
        break;
    }
}

// optional: return the size (in bytes) of the readable/writable space
// of the device.  Will default to 0 (non-seekable) if this is unimplemented
mx_off_t BlockDevice::virtio_block_get_size(mx_device_t* dev) {
    LTRACEF("dev %p\n", dev);

    // TODO: get a void * in the device structure so we dont need to do this
    Device* d = Device::MXDeviceToObj(dev);
    BlockDevice* bd = static_cast<BlockDevice*>(d);

    return bd->GetSize();
}

ssize_t BlockDevice::virtio_block_ioctl(mx_device_t* dev, uint32_t op, const void* in_buf, size_t in_len,
                 void* reply, size_t max) {
    LTRACEF("dev %p, op %u\n", dev, op);

    // TODO: get a void * in the device structure so we dont need to do this
    Device* d = Device::MXDeviceToObj(dev);
    BlockDevice* bd = static_cast<BlockDevice*>(d);

    switch (op) {
    case IOCTL_BLOCK_GET_SIZE: {
        uint64_t* size = static_cast<uint64_t*>(reply);
        if (max < sizeof(*size))
            return ERR_NOT_ENOUGH_BUFFER;
        *size = bd->GetSize();
        return sizeof(*size);
    }
    case IOCTL_BLOCK_GET_BLOCKSIZE: {
        uint64_t* blksize = static_cast<uint64_t*>(reply);
        if (max < sizeof(*blksize))
            return ERR_NOT_ENOUGH_BUFFER;
        *blksize = bd->GetBlockSize();
        return sizeof(*blksize);
    }
    case IOCTL_BLOCK_RR_PART: {
        // rebind to reread the partition table
        return device_rebind(dev);
    }
    default:
        return ERR_NOT_SUPPORTED;
    }
}

BlockDevice::BlockDevice(mx_driver_t* driver, mx_device_t* bus_device)
    : Device(driver, bus_device) {
    // so that Bind() knows how much io space to allocate
    bar0_size_ = 0x40;
}

BlockDevice::~BlockDevice() {
    // TODO: clean up allocated physical memory
}

mx_status_t BlockDevice::Init() {
    LTRACE_ENTRY;

    // reset the device
    Reset();

    // read our configuration
    CopyDeviceConfig(&config_, sizeof(config_));

    LTRACEF("capacity 0x%llx\n", config_.capacity);
    LTRACEF("size_max 0x%x\n", config_.size_max);
    LTRACEF("seg_max  0x%x\n", config_.seg_max);
    LTRACEF("blk_size 0x%x\n", config_.blk_size);

    // ack and set the driver status bit
    StatusAcknowledgeDriver();

    // XXX check features bits and ack/nak them

    // allocate the main vring
    auto err = vring_.Init(0, 128); // 128 matches legacy pci
    if (err < 0) {
        TRACEF("failed to allocate vring\n");
        return err;
    }

    // allocate a queue of block requests
    size_t size = sizeof(virtio_blk_req) * blk_req_count + sizeof(uint8_t) * blk_req_count;

    mx_status_t r = mx_alloc_device_memory(get_root_resource(), (uint32_t)size, &blk_req_pa_, (void**)&blk_req_);
    if (r < 0) {
        TRACEF("cannot alloc blk_req buffers %d\n", r);
        return r;
    }

    LTRACEF("allocated blk request at %p, physical address 0x%lx\n", blk_req_, blk_req_pa_);

    // responses are 32 words at the end of the allocated block
    blk_res_pa_ = blk_req_pa_ + sizeof(virtio_blk_req) * blk_req_count;
    blk_res_ = (uint8_t*)((uintptr_t)blk_req_ + sizeof(virtio_blk_req) * blk_req_count);

    LTRACEF("allocated blk responses at %p, physical address 0x%lx\n", blk_res_, blk_res_pa_);

    // start the interrupt thread
    StartIrqThread();

    // set DRIVER_OK
    StatusDriverOK();

    // initialize the mx_device and publish us
    device_ops_.iotxn_queue = &virtio_block_iotxn_queue;
    device_ops_.get_size = &virtio_block_get_size;
    device_ops_.ioctl = &virtio_block_ioctl;
    device_init(&device_, driver_, "virtio-block", &device_ops_);

    device_.protocol_id = MX_PROTOCOL_BLOCK;
    auto status = device_add(&device_, bus_device_);
    if (status < 0)
        return status;

    return NO_ERROR;
}

void BlockDevice::IrqRingUpdate() {
    LTRACE_ENTRY;

    // parse our descriptor chain, add back to the free queue
    auto free_chain = [this](vring_used_elem* used_elem) {
        uint32_t i = (uint16_t)used_elem->id;
        struct vring_desc* desc = vring_.DescFromIndex((uint16_t)i);
        auto head_desc = desc; // save the first element
        for (;;) {
            int next;

#if LOCAL_TRACE > 0
            virtio_dump_desc(desc);
#endif

            if (desc->flags & VRING_DESC_F_NEXT) {
                next = desc->next;
            } else {
                /* end of chain */
                next = -1;
            }

            vring_.FreeDesc((uint16_t)i);

            if (next < 0)
                break;
            i = next;
            desc = vring_.DescFromIndex((uint16_t)i);
        }

        // search our pending txn list to see if this completes it
        iotxn_t* txn;
        list_for_every_entry (&iotxn_list, txn, iotxn_t, node) {
            if (txn->context == head_desc) {
                LTRACEF("completes txn %p\n", txn);
                list_delete(&txn->node);
                txn->ops->complete(txn, NO_ERROR, txn->length);
                break;
            }
        }
    };

    // tell the ring to find free chains and hand it back to our lambda
    vring_.IrqRingUpdate(free_chain);
}

void BlockDevice::IrqConfigChange() {
    LTRACE_ENTRY;
}

void BlockDevice::QueueReadWriteTxn(iotxn_t* txn) {
    LTRACEF("txn %p\n", txn);

    AutoLock lock(lock_);

    bool write = (txn->opcode == IOTXN_OP_WRITE);

    // offset must be aligned to block size
    if (txn->offset % config_.blk_size) {
        TRACEF("offset 0x%llx is not aligned to sector size %u!\n", txn->offset, config_.blk_size);
        txn->ops->complete(txn, ERR_INVALID_ARGS, 0);
        return;
    }

    // constrain to device capacity
    txn->length = MIN(txn->length, GetSize() - txn->offset);

    // allocate and start filling out a block request
    auto index = alloc_blk_req();
    LTRACEF("request index %u\n", index);
    auto req = &blk_req_[index];
    req->type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    req->ioprio = 0;
    req->sector = txn->offset / 512;
    LTRACEF("blk_req type %u ioprio %u sector %llu\n",
            req->type, req->ioprio, req->sector);

    /* put together a transfer */
    uint16_t i;
    auto desc = vring_.AllocDescChain(3, &i);
    LTRACEF("after alloc chain desc %p, i %u\n", desc, i);

    /* point the iotxn at this head descriptor */
    txn->context = desc;

    /* set up the descriptor pointing to the head */
    desc->addr = blk_req_pa_ + index * sizeof(virtio_blk_req);
    desc->len = sizeof(struct virtio_blk_req);
    desc->flags |= VRING_DESC_F_NEXT;

#if LOCAL_TRACE > 0
    virtio_dump_desc(desc);
#endif

    /* set up the descriptor pointing to the buffer */
    desc = vring_.DescFromIndex(desc->next);

    mx_paddr_t pa;
    txn->ops->physmap(txn, &pa);

    desc->addr = (uint64_t)pa;
    desc->len = (uint32_t)txn->length;

    if (!write)
        desc->flags |= VRING_DESC_F_WRITE; /* mark buffer as write-only if its a block read */
    desc->flags |= VRING_DESC_F_NEXT;

#if LOCAL_TRACE > 0
    virtio_dump_desc(desc);
#endif

    /* set up the descriptor pointing to the response */
    desc = vring_.DescFromIndex(desc->next);
    desc->addr = blk_res_pa_ + index;
    desc->len = 1;
    desc->flags = VRING_DESC_F_WRITE;

#if LOCAL_TRACE > 0
    virtio_dump_desc(desc);
#endif

    // save the iotxn in a list
    list_add_tail(&iotxn_list, &txn->node);

    /* submit the transfer */
    vring_.SubmitChain(i);

    /* kick it off */
    vring_.Kick();
}

#if 0
ssize_t virtio_block_read_write(struct virtio_device *dev, void *buf, off_t offset, size_t len, bool write)
{
    struct virtio_block_dev *bdev = (struct virtio_block_dev *)dev->priv;

    uint16_t i;
    struct vring_desc *desc;
    paddr_t pa;
    vaddr_t va = (vaddr_t)buf;

    LTRACEF("dev %p, buf %p, offset 0x%llx, len %zu\n", dev, buf, offset, len);

    mutex_acquire(&bdev->lock);

    /* set up the request */
    bdev->blk_req->type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    bdev->blk_req->ioprio = 0;
    bdev->blk_req->sector = offset / 512;
    LTRACEF("blk_req type %u ioprio %u sector %llu\n",
            bdev->blk_req->type, bdev->blk_req->ioprio, bdev->blk_req->sector);

    /* put together a transfer */
    desc = virtio_alloc_desc_chain(dev, 0, 3, &i);
    LTRACEF("after alloc chain desc %p, i %u\n", desc, i);

    // XXX not cache safe.
    // At the moment only tested on arm qemu, which doesn't emulate cache.

    /* set up the descriptor pointing to the head */
    desc->addr = bdev->blk_req_phys;
    desc->len = sizeof(struct virtio_blk_req);
    desc->flags |= VRING_DESC_F_NEXT;

    /* set up the descriptor pointing to the buffer */
    desc = virtio_desc_index_to_desc(dev, 0, desc->next);
#if WITH_KERNEL_VM
    /* translate the first buffer */
    pa = vaddr_to_paddr((void *)va);
    // XXX check for error
    desc->addr = (uint64_t)pa;
    /* desc->len is filled in below */
#else
    desc->addr = (uint64_t)(uintptr_t)buf;
    desc->len = len;
#endif
    desc->flags |= write ? 0 : VRING_DESC_F_WRITE; /* mark buffer as write-only if its a block read */
    desc->flags |= VRING_DESC_F_NEXT;

#if WITH_KERNEL_VM
    /* see if we need to add more descriptors due to scatter gather */
    paddr_t next_pa = PAGE_ALIGN(pa + 1);
    desc->len = MIN(next_pa - pa, len);
    LTRACEF("first descriptor va 0x%lx desc->addr 0x%llx desc->len %u\n", va, desc->addr, desc->len);
    len -= desc->len;
    while (len > 0) {
        /* amount of source buffer handled by this iteration of the loop */
        size_t len_tohandle = MIN(len, PAGE_SIZE);

        /* translate the next page in the buffer */
        va = PAGE_ALIGN(va + 1);
        pa = vaddr_to_paddr((void *)va);
        // XXX check for error
        LTRACEF("va now 0x%lx, pa 0x%lx, next_pa 0x%lx, remaining len %zu\n", va, pa, next_pa, len);

        /* is the new translated physical address contiguous to the last one? */
        if (next_pa == pa) {
            LTRACEF("extending last one by %zu bytes\n", len_tohandle);
            desc->len += len_tohandle;
        } else {
            uint16_t next_i = virtio_alloc_desc(dev, 0);
            struct vring_desc *next_desc = virtio_desc_index_to_desc(dev, 0, next_i);
            DEBUG_ASSERT(next_desc);

            LTRACEF("doesn't extend, need new desc, allocated desc %i (%p)\n", next_i, next_desc);

            /* fill this descriptor in and put it after the last one but before the response descriptor */
            next_desc->addr = (uint64_t)pa;
            next_desc->len = len_tohandle;
            next_desc->flags = write ? 0 : VRING_DESC_F_WRITE; /* mark buffer as write-only if its a block read */
            next_desc->flags |= VRING_DESC_F_NEXT;
            next_desc->next = desc->next;
            desc->next = next_i;

            desc = next_desc;
        }
        len -= len_tohandle;
        next_pa += PAGE_SIZE;
    }
#endif

    /* set up the descriptor pointing to the response */
    desc = virtio_desc_index_to_desc(dev, 0, desc->next);
    desc->addr = bdev->blk_response_phys;
    desc->len = 1;
    desc->flags = VRING_DESC_F_WRITE;

    /* submit the transfer */
    virtio_submit_chain(dev, 0, i);

    /* kick it off */
    virtio_kick(dev, 0);

    /* wait for the transfer to complete */
    event_wait(&bdev->io_event);

    LTRACEF("status 0x%hhx\n", bdev->blk_response);

    mutex_release(&bdev->lock);

    return len;
}
#endif

} // namespace virtio
