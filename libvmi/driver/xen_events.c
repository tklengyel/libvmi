/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * This file is part of LibVMI.
 *
 * Author: Nasser Salim (njsalim@sandia.gov)
 * Author: Steven Maresca (steve@zentific.com)
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */
/* Portions of this header and dependent code is based upon that in xen-access, 
 *    from the official Xen source distribution.  That code carries the 
 *    following copyright notices and license.
 *
 * Copyright (c) 2011 Virtuata, Inc.
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp), based on
 *   xenpaging.c
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "libvmi.h"
#include "private.h"
#include "driver/xen.h"
#include "driver/xen_private.h"
#include "driver/xen_events.h"

#include <string.h>

/*----------------------------------------------------------------------------
 * Helper functions
 */

/* Only build if Xen and Xen memory events are explicitly enabled by the 
 *  configure script.
 *
 * Use the xenctrl interface version defined (from xenctrl.h) to validate
 *  that all the features we expect are present. This avoids build failures
 *  on 4.0.x which had some memory event functions defined, yet lacked
 *  all of the features LibVMI needs.
 */
#if ENABLE_XEN==1 && ENABLE_XEN_EVENTS==1 && XENCTRL_HAS_XC_INTERFACE
static xen_events_t *xen_get_events(vmi_instance_t vmi) 
{
    return xen_get_instance(vmi)->events;
}

#define ADDR (*(volatile long *) addr)
static inline int test_and_set_bit(int nr, volatile void *addr)
{
    int oldbit;
    asm volatile (
        "btsl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR)
        : "Ir" (nr), "m" (ADDR) : "memory");
    return oldbit;
}

/* Spinlock and mem event definitions */
#define SPIN_LOCK_UNLOCKED 0

static inline void spin_lock(spinlock_t *lock)
{
    while ( test_and_set_bit(1, lock) );
}

static inline void spin_lock_init(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

static inline void spin_unlock(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

#define xen_event_ring_lock_init(_m)  spin_lock_init(&(_m)->ring_lock)
#define xen_event_ring_lock(_m)       spin_lock(&(_m)->ring_lock)
#define xen_event_ring_unlock(_m)     spin_unlock(&(_m)->ring_lock)

int wait_for_event_or_timeout(xc_interface *xch, xc_evtchn *xce, unsigned long ms)
{
    struct pollfd fd = { .fd = xc_evtchn_fd(xce), .events = POLLIN | POLLERR };
    int port;
    int rc;

    rc = poll(&fd, 1, ms);
    if ( rc == -1 )
    {
        if (errno == EINTR)
            return 0;

        errprint("Poll exited with an error\n");
        goto err;
    }

    if ( rc == 1 )
    {
        port = xc_evtchn_pending(xce);
        if ( port == -1 )
        {
            errprint("Failed to read port from event channel\n");
            goto err;
        }

        rc = xc_evtchn_unmask(xce, port);
        if ( rc != 0 )
        {
            errprint("Failed to unmask event channel port\n");
            goto err;
        }
    }
    else
        port = -1;

    return port;

 err:
    return -errno;
}

int get_mem_event(xen_mem_event_t *mem_event, mem_event_request_t *req)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    xen_event_ring_lock(mem_event);

    back_ring = &mem_event->back_ring;
    req_cons = back_ring->req_cons;

    // Copy request
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    // Update ring
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;

    xen_event_ring_unlock(mem_event);

    return 0;
}

static int put_mem_response(xen_mem_event_t *mem_event, mem_event_response_t *rsp)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    xen_event_ring_lock(mem_event);

    back_ring = &mem_event->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    // Copy response
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    // Update ring
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);

    xen_event_ring_unlock(mem_event);

    return 0;
}

static int resume_domain(vmi_instance_t vmi, mem_event_response_t *rsp)
{
    xc_interface * xch;
    xen_events_t * xe;
    unsigned long dom;
    int ret;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);

    // Put the page info on the ring
    ret = put_mem_response(&xe->mem_event, rsp);
    if ( ret != 0 )
        return ret;

    // Tell Xen page is ready
    ret = xc_mem_access_resume(xch, dom, rsp->gfn);
    ret = xc_evtchn_notify(xe->mem_event.xce_handle, xe->mem_event.port);
    return ret;
}

status_t process_register(vmi_instance_t vmi,
                          registers_t reg,
                          mem_event_request_t req)
{

    struct event_handler_storage *store=(struct event_handler_storage *)g_hash_table_lookup(vmi->reg_event_handlers, &reg);
    if(store) {
            /* reg_event.equal allows you to set a reg event for
             *  a specific VALUE of the register (passed in req.gfn)
             */
            if(store->event->reg_event.equal && store->event->reg_event.equal != req.gfn)
                return VMI_SUCCESS;

            store->event->reg_event.value = req.gfn;
            store->event->vcpu_id = req.vcpu_id;

            /* TODO MARESCA: note that vmi_event_t lacks a flags member
             *   so we have no req.flags equivalent. might need to add
             *   e.g !!(req.flags & MEM_EVENT_FLAG_VCPU_PAUSED)  would be nice
             */
            store->callback(vmi, store->event);
            return VMI_SUCCESS;
    }
    return VMI_FAILURE;
}

status_t process_mem(vmi_instance_t vmi, mem_event_request_t req)
{
    event_iter_t i;
    vmi_event_t event, *eptr;
    event_callback_t callback;
    addr_t page;
    uint64_t npages;

    struct hvm_hw_cpu ctx;
    xc_interface * xch;
    unsigned long dom;
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);

    /* TODO, cleanup: ctx is unused here */
    xc_domain_hvm_getcontext_partial(xch, dom,
         HVM_SAVE_CODE(CPU), req.vcpu_id, &ctx, sizeof(ctx));

    struct event_handler_storage *store=(struct event_handler_storage *)g_hash_table_lookup(vmi->mem_event_handlers, &req.gfn);
    if(store && store->event) {
                store->event->mem_event.gla = req.gla;
                store->event->mem_event.gfn = req.gfn;
                store->event->mem_event.offset = req.offset;
                store->event->vcpu_id = req.vcpu_id;

                if(req.access_r) store->event->mem_event.out_access = VMI_MEM_R;
                else if(req.access_w) store->event->mem_event.out_access = VMI_MEM_W;
                else if(req.access_x) store->event->mem_event.out_access = VMI_MEM_X;

                /* TODO MARESCA: decide whether it's worthwhile to emulate xen-access here and call the following
                 *    note: the 'access' variable is basically discarded in that spot. perhaps it's really only called
                 *    to validate that the event is accessible (maybe that it's not consumed elsewhere??)
                 * hvmmem_access_t access;
                 * rc = xc_hvm_get_mem_access(xch, domain_id, event.mem_event.gfn, &access);
                 */
                store->callback(vmi, store->event);

                return VMI_SUCCESS;
    }
    return VMI_FAILURE;
}

//----------------------------------------------------------------------------
// Driver functions

void xen_events_destroy(vmi_instance_t vmi)
{
    int rc;
    xc_interface * xch;
    xen_events_t * xe;
    unsigned long dom;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);

    if ( xe == NULL )
        return;

    // Turn off mem events
#ifdef XENEVENT42
    rc = xc_mem_access_disable(xch, dom);
    munmap(xe->mem_event.ring_page, getpagesize());
#elif XENEVENT41
    rc = xc_mem_event_disable(xch, dom);

    if (xe->mem_event.ring_page != NULL) {
        munlock(xe->mem_event.ring_page, getpagesize());
        free(xe->mem_event.ring_page);
    }

    if (xe->mem_event.shared_page != NULL) {
        munlock(xe->mem_event.shared_page, getpagesize());
        free(xe->mem_event.shared_page);
    }
#endif

    if ( rc != 0 )
    {
        errprint("Error disabling mem events.\n");
    }

    /* TODO MARESCA - might want the evtchn_bind flag like in xen-access here
     * for when this function is called before it was bound
     */
    // Unbind VIRQ
    rc = xc_evtchn_unbind(xe->mem_event.xce_handle, xe->mem_event.port);
    if ( rc != 0 )
    {
        errprint("Error unbinding event port\n");
    }
    xe->mem_event.port = -1;

    // Close event channel
    rc = xc_evtchn_close(xe->mem_event.xce_handle);
    if ( rc != 0 )
    {
        errprint("Error closing event channel\n");
    }
    xe->mem_event.xce_handle = NULL;

    free(xe);
}

status_t xen_events_init(vmi_instance_t vmi)
{
    xen_events_t * xe;
    xc_interface * xch;
    xc_domaininfo_t * dom_info;
    unsigned long dom;
    unsigned long ring_pfn, mmap_pfn;
    int rc;

    // Allocate memory
    xe = malloc(sizeof(xen_events_t));
    memset(xe, 0, sizeof(xen_events_t));

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);

    dbprint("Init xen events with xch == %llx\n", (unsigned long long)xch);

    // Initialise lock
    xen_event_ring_lock_init(&xe->mem_event);

#ifdef XENEVENT42
    // Initialise shared page
    xc_get_hvm_param(xch, dom, HVM_PARAM_ACCESS_RING_PFN, &ring_pfn);
    mmap_pfn = ring_pfn;
    xe->mem_event.ring_page =
        xc_map_foreign_batch(xch, dom, PROT_READ | PROT_WRITE, &mmap_pfn, 1);
    if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
    {
        /* Map failed, populate ring page */
        rc = xc_domain_populate_physmap_exact(xch,
                                              dom,
                                              1, 0, 0, &ring_pfn);
        if ( rc != 0 )
        {
            errprint("Failed to populate ring gfn\n");
            goto err;
        }

        mmap_pfn = ring_pfn;
        xe->mem_event.ring_page =
            xc_map_foreign_batch(xch, dom,
                                    PROT_READ | PROT_WRITE, &mmap_pfn, 1);
        if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
        {
            errprint("Could not map the ring page\n");
            goto err;
        }
    }

#elif XENEVENT41

    rc = posix_memalign(&xe->mem_event.ring_page, getpagesize(), getpagesize());
    if (rc != 0 ) {
        errprint("Could not allocate the ring page!\n");
        goto err;
    }

    rc = mlock(xe->mem_event.ring_page, getpagesize());
    if (rc != 0 ) {
        errprint("Could not lock the ring page!\n");
        free(xe->mem_event.ring_page);
        xe->mem_event.ring_page = NULL;
        goto err;
    }

    rc = posix_memalign(&xe->mem_event.shared_page, getpagesize(), getpagesize());
    if (rc != 0 ) {
        errprint("Could not allocate the shared page!\n");
        goto err;
    }

    rc = mlock(xe->mem_event.shared_page, getpagesize());
    if (rc != 0 ) {
        errprint("Could not lock the shared page!\n");
        free(xe->mem_event.shared_page);
        xe->mem_event.shared_page = NULL;
        goto err;
    }

#endif

#ifdef XENEVENT42
    // Initialise Xen
    rc = xc_mem_access_enable(xch, dom, &(xe->mem_event.evtchn_port));
#elif XENEVENT41
    rc = xc_mem_event_enable(xch, dom, xe->mem_event.shared_page,
                                 xe->mem_event.ring_page);

#endif

    if ( rc != 0 )
    {
        switch ( errno ) {
            case EBUSY:
                errprint("events are (or were) active on this domain\n");
                break;
            case ENODEV:
                errprint("EPT not supported for this guest\n");
                break;
            default:
                errprint("Error initialising memory events: %s\n", strerror(errno));
                break;
        }
        goto err;
    }

    // Open event channel
    xe->mem_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( xe->mem_event.xce_handle == NULL )
    {
        errprint("Failed to open event channel\n");
        goto err;
    }

    // Bind event notification
#ifdef XENEVENT42
    rc = xc_evtchn_bind_interdomain(
          xe->mem_event.xce_handle, dom, xe->mem_event.evtchn_port);
#elif XENEVENT41
    rc = xc_evtchn_bind_interdomain(
          xe->mem_event.xce_handle, dom, xe->mem_event.shared_page->port);
#endif

    if ( rc < 0 )
    {
        errprint("Failed to bind event channel\n");
        goto err;
    }

    xe->mem_event.port = rc;
    dbprint("Bound to event channel on port == %d\n", xe->mem_event.port);

    // Initialise ring
    SHARED_RING_INIT((mem_event_sring_t *)xe->mem_event.ring_page);
    BACK_RING_INIT(&xe->mem_event.back_ring,
                   (mem_event_sring_t *)xe->mem_event.ring_page,
                   getpagesize());

    /* Now that the ring is set, remove it from the guest's physmap */
    if ( xc_domain_decrease_reservation_exact(xch,
                    dom, 1, 0, &ring_pfn) )
        errprint("Failed to remove ring from guest physmap");

    // Get domaininfo
    /* TODO MARESCA non allocated would work fine here via &dominfo below */
    dom_info = malloc(sizeof(xc_domaininfo_t));
    if ( dom_info == NULL )
    {
        errprint("Error allocating memory for domain info\n");
        goto err;
    }

    rc = xc_domain_getinfolist(xch, dom, 1, dom_info);
    if ( rc != 1 )
    {
        errprint("Error getting domain info\n");
        goto err;
    }

    // This is mostly nice for setting global access.
    // There may be a better way to manage this.
    xe->mem_event.max_pages = dom_info->max_pages;
    free(dom_info);

    xen_get_instance(vmi)->events = xe;
    return VMI_SUCCESS;

 err:
    xen_events_destroy(vmi);
    return VMI_FAILURE;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t event)
{
    xc_interface * xch = xen_get_xchandle(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    int value = HVMPME_mode_disabled;
    int hvm_param;

    switch(event.in_access){
        case VMI_REG_N: break;
        case VMI_REG_W:
            value = HVMPME_mode_sync;
            if(event.async)
                value = HVMPME_mode_async;
            if(event.onchange)
                /* MARESCA note bugfix was applied here
                 *  Previously, was value = HVMPME_onchangeonly;
                 */
                value |= HVMPME_onchangeonly;
            break;
        case VMI_REG_R:
        case VMI_REG_RW:
            errprint("Register read events are unavailable in Xen.\n");
            return VMI_FAILURE;
            break;
        default:
            errprint("Unknown register access mode: %d\n", event.in_access);
            return VMI_FAILURE;
    }

    switch(event.reg){
        case CR0:
            hvm_param = HVM_PARAM_MEMORY_EVENT_CR0;
            break;
        case CR3:
            hvm_param = HVM_PARAM_MEMORY_EVENT_CR3;
            break;
        case CR4:
            hvm_param = HVM_PARAM_MEMORY_EVENT_CR4;
            break;
        default:
            errprint("Tried to register for unsupported register event.\n");
            return VMI_FAILURE;
    }
    if(xc_set_hvm_param(xch, dom, hvm_param, value))
        return VMI_FAILURE;
    return VMI_SUCCESS;
}

status_t xen_set_mem_access(vmi_instance_t vmi, mem_event_t event)
{
    int rc;
    hvmmem_access_t access;
    xc_interface * xch = xen_get_xchandle(vmi);
    xen_events_t * xe = xen_get_events(vmi);
    unsigned long dom = xen_get_domainid(vmi);
    uint64_t npages = event.npages > xe->mem_event.max_pages
        ? xe->mem_event.max_pages : event.npages;

    // Convert betwen vmi_mem_access_t and hvmmem_access_t
    // Xen does them backwards....
    switch(event.in_access){
        case VMI_MEM_N: access = HVMMEM_access_rwx; break;
        case VMI_MEM_R: access = HVMMEM_access_wx; break;
        case VMI_MEM_W: access = HVMMEM_access_rx; break;
        case VMI_MEM_X: access = HVMMEM_access_rw; break;
        case VMI_MEM_RW: access = HVMMEM_access_x; break;
        case VMI_MEM_RX: access = HVMMEM_access_w; break;
        case VMI_MEM_WX: access = HVMMEM_access_r; break;
        case VMI_MEM_RWX: access = HVMMEM_access_n; break;
        case VMI_MEM_X_ON_WRITE: access = HVMMEM_access_rx2rw; break;
    }

    dbprint("--Setting memaccess for domain %lu on page: %"PRIu64" npages: %"PRIu64"\n",
        dom, event.page, npages);
    if((rc = xc_hvm_set_mem_access(xch, dom, access, event.page, npages))){
        errprint("xc_hvm_set_mem_access failed with code: %d\n", rc);
        return VMI_FAILURE;
    }
    dbprint("--Done Setting memaccess on page: %"PRIu64"\n", event.page);
    return VMI_SUCCESS;
}

status_t xen_set_int3_access(vmi_instance_t vmi, int enabled)
{
    int param = HVMPME_mode_disabled;
    if(enabled)
        param = HVMPME_mode_sync;

    return xc_set_hvm_param(
        xen_get_xchandle(vmi), xen_get_domainid(vmi),
        HVM_PARAM_MEMORY_EVENT_INT3, param);
}

status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout)
{
    xc_interface * xch;
    xen_events_t * xe;
    mem_event_request_t req;
    mem_event_response_t rsp;
    unsigned long dom;

    int rc = -1;
    status_t vrc = VMI_FAILURE;

    /* TODO determine whether we should force the required=1 for
     *   singlestep and int3, for which that is a necessity.
     * Alternatively, an error could be issued
     */
    int required = 0;

    // Get xen handle and domain.
    xch = xen_get_xchandle(vmi);
    dom = xen_get_domainid(vmi);
    xe = xen_get_events(vmi);

    // Set whether the access listener is required
    rc = xc_domain_set_access_required(xch, dom, required);
    if ( rc < 0 ) {
        errprint("Error %d setting mem_access listener required\n", rc);
    }


    dbprint("--Waiting for xen events...(%"PRIu32" ms)\n", timeout);
    rc = wait_for_event_or_timeout(xch, xe->mem_event.xce_handle, timeout);
    if ( rc < -1 ) {
        errprint("Error while waiting for event.\n");
        return VMI_FAILURE;
    }

    while ( RING_HAS_UNCONSUMED_REQUESTS(&xe->mem_event.back_ring) ) {
        rc = get_mem_event(&xe->mem_event, &req);
        if ( rc != 0 ) {
            errprint("Error getting event.\n");
            return VMI_FAILURE;
        }

        memset( &rsp, 0, sizeof (rsp) );
        rsp.vcpu_id = req.vcpu_id;
        rsp.flags = req.flags;

        switch(req.reason){
            case MEM_EVENT_REASON_VIOLATION:
                dbprint("--Caught mem event!\n");
                rsp.gfn = req.gfn;
                rsp.p2mt = req.p2mt;
                vrc = process_mem(vmi, req);

                /*MARESCA do we need logic here to reset flags on a page? see xen-access.c
                 *    specifically regarding write/exec/int3 inspection and the code surrounding
                 *    the variables default_access and after_first_access
                 */

                break;
            case MEM_EVENT_REASON_CR0:
                vrc = process_register(vmi, CR0, req);
                break;
            case MEM_EVENT_REASON_CR3:
                dbprint("--Caught CR3 event!\n");
                vrc = process_register(vmi, CR3, req);
                break;
            case MEM_EVENT_REASON_CR4:
                vrc = process_register(vmi, CR4, req);
                break;
            case MEM_EVENT_REASON_INT3:
                /* TODO MARESCA need to handle this;
                 * see xen-unstable.hg/tools/include/xen/mem_event.h
                 */
            case MEM_EVENT_REASON_SINGLESTEP:
                /* TODO MARESCA need to handle this;
                 * see xen-unstable.hg/tools/include/xen/mem_event.h
                 */
            default:
                errprint("UNKNOWN REASON CODE %d\n", req.reason);
                vrc = VMI_FAILURE;
        }

        rc = resume_domain(vmi, &rsp);
        if ( rc != 0 ) {
            errprint("Error resuming domain.\n");
            return VMI_FAILURE;
        }
    }

    dbprint("--Finished handling event.\n");
    return vrc;
}
#else
status_t xen_events_listen(vmi_instance_t vmi, uint32_t timeout){
	return VMI_FAILURE;
}

status_t xen_set_reg_access(vmi_instance_t vmi, reg_event_t event){
	return VMI_FAILURE;
}

status_t xen_set_mem_access(vmi_instance_t vmi, mem_event_t event){
	return VMI_FAILURE;
}
status_t xen_events_init(vmi_instance_t vmi){
	return VMI_FAILURE;
}
void xen_events_destroy(vmi_instance_t vmi){
}
#endif /* ENABLE_XEN */
