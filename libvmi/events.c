/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Nasser Salim (njsalim@sandia.gov)
 * Author: Steven Maresca (steven.maresca@zentific.com)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
 *
 * This file is part of LibVMI.
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

#define _GNU_SOURCE
#include <glib.h>

#include "private.h"
#include "driver/driver_wrapper.h"

vmi_mem_access_t combine_mem_access(vmi_mem_access_t base, vmi_mem_access_t add)
{

    if (add == base)
        return base;

    if (add == VMI_MEMACCESS_N)
        return base;
    if (base == VMI_MEMACCESS_N)
        return add;

    // Can't combine rights with X_ON_WRITE
    if (add == VMI_MEMACCESS_W2X || add == VMI_MEMACCESS_RWX2N)
        return VMI_MEMACCESS_INVALID;
    if (base == VMI_MEMACCESS_W2X || base == VMI_MEMACCESS_RWX2N)
        return VMI_MEMACCESS_INVALID;

    return (base | add);

}

//----------------------------------------------------------------------------
//  General event callback management.

gboolean event_entry_free(gpointer key, gpointer value, gpointer data)
{
    vmi_instance_t vmi = (vmi_instance_t) data;
    vmi_event_t *event = (vmi_event_t*) value;
    vmi_clear_event(vmi, event, NULL);
    g_free(key);
    return TRUE;
}

void step_wrapper_free(gpointer value, gpointer data)
{
    vmi_instance_t vmi = (vmi_instance_t) data;
    step_and_reg_event_wrapper_t *wrap = (step_and_reg_event_wrapper_t*) value;
    vmi_event_t *single_event = vmi_get_singlestep_event(vmi, wrap->vcpu_id);

    if(single_event) {
        // Not calling vmi_clear_event here as during shutdown
        // it doesn't remove the event from the GHashTable
        // and results in a use-after-free.
        if(VMI_SUCCESS == driver_stop_single_step(vmi, wrap->vcpu_id))
        {
            g_hash_table_remove(vmi->ss_events, &(wrap->vcpu_id));
        }

       free(single_event);
    }

    free(wrap);
}

void step_event_free(vmi_event_t *event, status_t rc)
{
    if ( VMI_SUCCESS == rc )
        g_free(event);
}

void events_init(vmi_instance_t vmi)
{
    vmi->interrupt_events = g_hash_table_new(g_int_hash, g_int_equal);
    vmi->mem_events_on_gfn = g_hash_table_new(g_int64_hash, g_int64_equal);
    vmi->mem_events_generic = g_hash_table_new(g_int_hash, g_int_equal);
    vmi->reg_events = g_hash_table_new(g_int_hash, g_int_equal);
    vmi->ss_events = g_hash_table_new(g_int_hash, g_int_equal);
    vmi->clear_events = g_hash_table_new(g_int64_hash, g_int64_equal);
}

void events_destroy(vmi_instance_t vmi)
{
    if (vmi->mem_events_on_gfn)
    {
        dbprint(VMI_DEBUG_EVENTS, "Destroying memaccess on gfn events\n");
        g_hash_table_foreach_remove(vmi->mem_events_on_gfn, event_entry_free, vmi);
        g_hash_table_destroy(vmi->mem_events_on_gfn);
        vmi->mem_events_on_gfn = NULL;
    }

    if (vmi->mem_events_generic)
    {
        dbprint(VMI_DEBUG_EVENTS, "Destroying memaccess generic events\n");
        g_hash_table_foreach_remove(vmi->mem_events_generic, event_entry_free, vmi);
        g_hash_table_destroy(vmi->mem_events_generic);
        vmi->mem_events_generic = NULL;
    }

    if (vmi->reg_events)
    {
        dbprint(VMI_DEBUG_EVENTS, "Destroying register events\n");
        g_hash_table_foreach_steal(vmi->reg_events, event_entry_free, vmi);
        g_hash_table_destroy(vmi->reg_events);
        vmi->reg_events = NULL;
    }

    if (vmi->step_events)
    {
        g_slist_foreach(vmi->step_events, step_wrapper_free, vmi);
        g_slist_free(vmi->step_events);
        vmi->step_events = NULL;
    }

    if (vmi->ss_events)
    {
        dbprint(VMI_DEBUG_EVENTS, "Destroying singlestep events\n");
        g_hash_table_foreach_remove(vmi->ss_events, event_entry_free, vmi);
        g_hash_table_destroy(vmi->ss_events);
        vmi->ss_events = NULL;
    }

    if (vmi->interrupt_events)
    {
        dbprint(VMI_DEBUG_EVENTS, "Destroying interrupt events\n");
        g_hash_table_foreach_steal(vmi->interrupt_events, event_entry_free, vmi);
        g_hash_table_destroy(vmi->interrupt_events);
        vmi->interrupt_events = NULL;
    }

    if ( vmi->clear_events )
    {
        g_hash_table_destroy(vmi->clear_events);
        vmi->clear_events = NULL;
    }
}

status_t register_interrupt_event(vmi_instance_t vmi, vmi_event_t *event)
{

    status_t rc = VMI_FAILURE;

    if (NULL != g_hash_table_lookup(vmi->interrupt_events, &(event->interrupt_event.intr)))
    {
        dbprint(VMI_DEBUG_EVENTS, "An event is already registered on this interrupt: %d\n",
                event->interrupt_event.intr);
    }
    else if (VMI_SUCCESS == driver_set_intr_access(vmi, &event->interrupt_event, 1))
    {
        gint *intr = g_malloc0(sizeof(gint));
        *intr = event->interrupt_event.intr;

        g_hash_table_insert(vmi->interrupt_events, intr, event);
        dbprint(VMI_DEBUG_EVENTS, "Enabled event on interrupt: %d\n", event->interrupt_event.intr);
        rc = VMI_SUCCESS;
    }

    return rc;
}

status_t register_reg_event(vmi_instance_t vmi, vmi_event_t *event)
{

    status_t rc = VMI_FAILURE;

    if (NULL != g_hash_table_lookup(vmi->reg_events, &(event->reg_event.reg)))
    {
        dbprint(VMI_DEBUG_EVENTS, "An event is already registered on this reg: %d\n",
                event->reg_event.reg);
    }
    else if (VMI_SUCCESS == driver_set_reg_access(vmi, &event->reg_event))
    {
        gint *reg = g_malloc0(sizeof(gint));
        *reg = event->reg_event.reg;

        g_hash_table_insert(vmi->reg_events, reg, event);
        dbprint(VMI_DEBUG_EVENTS, "Enabled register event on reg: %d\n", event->reg_event.reg);
        rc = VMI_SUCCESS;
    }

    return rc;
}

event_response_t step_and_reg_events(vmi_instance_t vmi, vmi_event_t *singlestep_event)
{

    /* We copy the list here as the user may add to it in the callback. */
    GSList *reg_list = NULL, *loop = NULL;
    for(loop = vmi->step_events; loop; loop = loop->next) {
        reg_list = g_slist_prepend(reg_list, loop->data);
    }

    /* Clean the existing list preemptively. */
    g_slist_free(vmi->step_events);
    vmi->step_events = NULL;

    GSList *reg_list_head = reg_list;
    GSList *remain = NULL;

    while (reg_list)
    {
        step_and_reg_event_wrapper_t *wrap =
                (step_and_reg_event_wrapper_t *) reg_list->data;

        if (wrap->vcpu_id == singlestep_event->vcpu_id)
        {
            wrap->steps--;
        }

        if (0 == wrap->steps)
        {
            if (wrap->cb)
            {
                wrap->cb(vmi, wrap->event);
            }
            else
            {
                vmi_register_event(vmi, wrap->event);
            }

            --(vmi->step_vcpus[wrap->vcpu_id]);
            if (!vmi->step_vcpus[wrap->vcpu_id])
            {
                // No more events on this vcpu need registering
                vmi_clear_event(vmi, singlestep_event, step_event_free);
            }

            free(wrap);
        }
        else
        {
            remain = g_slist_prepend(remain, wrap);
        }

        reg_list = reg_list->next;
    }

    g_slist_free(reg_list_head);

    /* Concat the remainder of this list with whatever the user set. */
    if (vmi->step_events)
        vmi->step_events = g_slist_concat(remain, vmi->step_events);
    else
        vmi->step_events = remain;

    return 0;
}

static status_t register_mem_event_generic(vmi_instance_t vmi, vmi_event_t *event)
{
    if ( event->mem_event.physical_address != ~0 )
    {
        dbprint(VMI_DEBUG_EVENTS, "Physical address must be ~0 for generic mem event types.\n");
        return VMI_FAILURE;
    }

    if ( g_hash_table_size(vmi->mem_events_on_gfn) )
    {
        dbprint(VMI_DEBUG_EVENTS, "You already have page specific mem event handlers registered.\n");
        return VMI_FAILURE;
    }

    if ( g_hash_table_lookup(vmi->mem_events_generic, &event->mem_event.in_access) )
    {
        dbprint(VMI_DEBUG_EVENTS, "An event is already registered for this tpye of access violation\n");
        return VMI_FAILURE;
    }

    gint *access = g_malloc0(sizeof(gint));
    *access = event->mem_event.in_access;

    g_hash_table_insert(vmi->mem_events_generic, access, event);
    return VMI_SUCCESS;
}

static status_t register_mem_event_on_gfn(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t page_key = event->mem_event.physical_address >> 12;

    if ( VMI_MEMACCESS_INVALID == event->mem_event.in_access )
    {
        dbprint(VMI_DEBUG_EVENTS, "Invalid VMI_MEMACCESS requested: %d\n",
                event->mem_event.in_access);
        return VMI_FAILURE;
    }

    if ( g_hash_table_size(vmi->mem_events_generic) )
    {
        dbprint(VMI_DEBUG_EVENTS, "You already have generic mem event handlers registered.\n");
        return VMI_FAILURE;
    }

    // Page already has an event registered
    if ( g_hash_table_lookup(vmi->mem_events_on_gfn, &page_key) )
    {
        dbprint(VMI_DEBUG_EVENTS,
                "An event is already registered on this page: %"PRIu64"\n",
                page_key);
        return VMI_FAILURE;
    }

    if (VMI_SUCCESS == driver_set_mem_access(vmi, page_key,
                                             event->mem_event.in_access,
                                             event->slat_id))
    {
        g_hash_table_insert(vmi->mem_events_on_gfn, g_memdup(&page_key, sizeof(addr_t)), event);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

status_t register_mem_event(vmi_instance_t vmi, vmi_event_t *event)
{
    if ( event->mem_event.generic )
        return register_mem_event_generic(vmi, event);
    else
        return register_mem_event_on_gfn(vmi, event);
}

status_t register_singlestep_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;
    uint32_t vcpu;
    uint32_t *vcpu_i = NULL;

    for (vcpu=0; vcpu < vmi->num_vcpus; vcpu++)
    {
        if (CHECK_VCPU_SINGLESTEP(event->ss_event, vcpu))
        {
            if (NULL != g_hash_table_lookup(vmi->ss_events, &vcpu))
            {
                dbprint(VMI_DEBUG_EVENTS, "An event is already registered on this vcpu: %u\n",
                        vcpu);
                goto done;
            }
        }
    }

    if (VMI_FAILURE == driver_start_single_step(vmi, &event->ss_event))
        goto done;

    dbprint(VMI_DEBUG_EVENTS, "Enabling single step\n");

    for (vcpu=0; vcpu < vmi->num_vcpus; vcpu++)
    {
        if (CHECK_VCPU_SINGLESTEP(event->ss_event, vcpu))
        {
            vcpu_i = malloc(sizeof(uint32_t));
            *vcpu_i = vcpu;
            g_hash_table_insert(vmi->ss_events, vcpu_i, event);
         }
    }

    rc = VMI_SUCCESS;

done:
    return rc;
}

status_t register_guest_requested_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;

    if ( !vmi->guest_requested_event )
    {
        rc = driver_set_guest_requested_event(vmi, 1);
        if ( VMI_SUCCESS == rc )
            vmi->guest_requested_event = event;
    };

    return rc;
}

status_t register_cpuid_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;

    if ( !vmi->cpuid_event )
    {
        rc = driver_set_cpuid_event(vmi, 1);
        if ( VMI_SUCCESS == rc )
            vmi->cpuid_event = event;
    };

    return rc;
}

status_t register_debug_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;

    if ( !vmi->debug_event )
    {
        rc = driver_set_cpuid_event(vmi, 1);
        if ( VMI_SUCCESS == rc )
            vmi->debug_event = event;
    };

    return rc;
}

status_t clear_interrupt_event(vmi_instance_t vmi, vmi_event_t *event)
{

    status_t rc = VMI_FAILURE;

    if (NULL != g_hash_table_lookup(vmi->interrupt_events, &(event->interrupt_event.intr)))
    {
        dbprint(VMI_DEBUG_EVENTS, "Disabling event on interrupt: %d\n", event->interrupt_event.intr);
        rc = driver_set_intr_access(vmi, &event->interrupt_event, 0);
        if (!vmi->shutting_down && rc == VMI_SUCCESS)
        {
            g_hash_table_remove(vmi->interrupt_events, &(event->interrupt_event.intr));
        }
    }

    return rc;

}

status_t clear_reg_event(vmi_instance_t vmi, vmi_event_t *event)
{

    status_t rc = VMI_FAILURE;
    vmi_reg_access_t original_in_access = VMI_REGACCESS_N;

    if (NULL != g_hash_table_lookup(vmi->reg_events, &(event->reg_event.reg)))
    {
        dbprint(VMI_DEBUG_EVENTS, "Disabling register event on reg: %d\n", event->reg_event.reg);
        original_in_access = event->reg_event.in_access;
        event->reg_event.in_access = VMI_REGACCESS_N;
        rc = driver_set_reg_access(vmi, &event->reg_event);
        event->reg_event.in_access = original_in_access;

        if (!vmi->shutting_down && rc == VMI_SUCCESS)
        {
            g_hash_table_remove(vmi->reg_events, &(event->reg_event.reg));
        }
    }

    return rc;

}

status_t clear_mem_event(vmi_instance_t vmi, vmi_event_t *event)
{
    /* For generic events we just have to remove the handler */
    if ( event->mem_event.generic )
    {
        /* No point if we are shutting down because we will just destroy the table anyway */
        if ( !vmi->shutting_down )
            g_hash_table_remove(vmi->mem_events_generic, &event->mem_event.in_access);

        return VMI_SUCCESS;
    }

    /* For gfn-based events we also clear the page with the driver */
    addr_t page_key = event->mem_event.physical_address >> 12;
    status_t rc = driver_set_mem_access(vmi, page_key,
                    VMI_MEMACCESS_N, event->slat_id);

    dbprint(VMI_DEBUG_EVENTS, "Disabling memevent on page 0x%"PRIx32" in view %"PRIu32": %s\n",
            page_key, event->slat_id,
            (rc == VMI_FAILURE) ? "failed" : "success");

    if ( !vmi->shutting_down && rc == VMI_SUCCESS )
        g_hash_table_remove(vmi->mem_events_on_gfn, &page_key);

    return rc;

}

status_t clear_singlestep_event(vmi_instance_t vmi, vmi_event_t *event)
{

    status_t rc = VMI_FAILURE;
    uint32_t vcpu = 0;

    for (; vcpu < vmi->num_vcpus; vcpu++)
    {
        if (CHECK_VCPU_SINGLESTEP(event->ss_event, vcpu))
        {
            dbprint(VMI_DEBUG_EVENTS, "Disabling single step on vcpu: %u\n", vcpu);
            rc = driver_stop_single_step(vmi, vcpu);
            if (!vmi->shutting_down && rc == VMI_SUCCESS)
            {
                g_hash_table_remove(vmi->ss_events, &(vcpu));
            }
        }
    }

    if(0 == g_hash_table_size(vmi->ss_events))
    {
        vmi_shutdown_single_step(vmi);
    }

    return rc;
}

status_t clear_guest_requested_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;

    if ( vmi->guest_requested_event ) {
        rc = driver_set_guest_requested_event(vmi, 0);

        if ( VMI_SUCCESS == rc )
            vmi->guest_requested_event = NULL;
    }

    return rc;
}

status_t clear_cpuid_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;

    if ( vmi->cpuid_event ) {
        rc = driver_set_cpuid_event(vmi, 0);

        if ( VMI_SUCCESS == rc)
            vmi->cpuid_event = NULL;
    }

    return rc;
}

status_t clear_debug_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t rc = VMI_FAILURE;

    if ( vmi->debug_event ) {
        rc = driver_set_debug_event(vmi, 0);

        if ( VMI_SUCCESS == rc )
            vmi->debug_event = NULL;
    }

    return rc;
}

//----------------------------------------------------------------------------
// Public event functions.

vmi_event_t *vmi_get_reg_event(vmi_instance_t vmi, registers_t reg)
{
    return g_hash_table_lookup(vmi->reg_events, &reg);
}

vmi_event_t *vmi_get_mem_event(vmi_instance_t vmi, addr_t physical_address, vmi_mem_access_t access)
{
    vmi_event_t *ret = g_hash_table_lookup(vmi->mem_events_generic, &access);
    if ( ret )
        return ret;

    addr_t page_key = physical_address >> 12;
    return g_hash_table_lookup(vmi->mem_events_on_gfn, &page_key);
}

status_t vmi_set_mem_event(vmi_instance_t vmi, addr_t physical_address,
                           vmi_mem_access_t access, uint16_t slat_id)
{
    if ( VMI_MEMACCESS_N != access )
    {
        bool handler_found = 0;
        GHashTableIter i;
        vmi_mem_access_t *key = NULL;
        vmi_event_t *event = NULL;

        ghashtable_foreach(vmi->mem_events_generic, i, &key, &event) {
            if ( (*key) & access ) {
                handler_found =1;
                break;
            }
        }

        if ( !handler_found )
        {
            dbprint(VMI_DEBUG_EVENTS, "It is unsafe to set mem access without a handler being registered!\n");
            return VMI_FAILURE;
        }
    }

    return driver_set_mem_access(vmi, physical_address >> 12, access, slat_id);
}

status_t vmi_register_event(vmi_instance_t vmi, vmi_event_t* event)
{
    status_t rc = VMI_FAILURE;

    if (!(vmi->init_mode & VMI_INIT_EVENTS))
    {
        dbprint(VMI_DEBUG_EVENTS, "LibVMI wasn't initialized with events!\n");
        return VMI_FAILURE;
    }
    if (!event)
    {
        dbprint(VMI_DEBUG_EVENTS, "No event given!\n");
        return VMI_FAILURE;
    }
    if (event->version > VMI_EVENTS_VERSION)
    {
        dbprint(VMI_DEBUG_EVENTS, "The caller requires a newer version of LibVMI!\n");
        return VMI_FAILURE;
    }
    if (event->version < VMI_EVENTS_VERSION)
    {
        /*
         * Note: backwards-compatibility can be implemented by defining an internal
         *  header for the older ABI and handling the calls according to the version
         *  that was requested.
         *  This is left as a TODO for when it becomes necessary.
         */
        dbprint(VMI_DEBUG_EVENTS, "The caller requires an older version of LibVMI!\n");
        return VMI_FAILURE;
    }
    if (!event->callback)
    {
        dbprint(VMI_DEBUG_EVENTS, "No event callback function specified!\n");
        return VMI_FAILURE;
    }

    switch (event->type)
    {

    case VMI_EVENT_REGISTER:
        rc = register_reg_event(vmi, event);
        break;
    case VMI_EVENT_MEMORY:
        rc = register_mem_event(vmi, event);
        break;
    case VMI_EVENT_SINGLESTEP:
        rc = register_singlestep_event(vmi, event);
        break;
    case VMI_EVENT_INTERRUPT:
        rc = register_interrupt_event(vmi, event);
        break;
    case VMI_EVENT_GUEST_REQUEST:
        rc = register_guest_requested_event(vmi, event);
        break;
    case VMI_EVENT_CPUID:
        rc = register_cpuid_event(vmi, event);
        break;
    case VMI_EVENT_DEBUG_EXCEPTION:
        rc = register_debug_event(vmi, event);
        break;
    default:
        dbprint(VMI_DEBUG_EVENTS, "Unknown event type: %d\n", event->type);
        break;
    }

    return rc;
}

status_t vmi_clear_event(vmi_instance_t vmi, vmi_event_t* event,
                         vmi_event_free_t free_routine)
{
    status_t rc = VMI_FAILURE;

    if (!(vmi->init_mode & VMI_INIT_EVENTS))
    {
        return VMI_FAILURE;
    }

    /*
     * We can't clear events when in an event callback rigt away
     * because there may be more events in the queue already
     * that were triggered by the event we would be clearing now.
     * The driver needs to process this list when it can safely.
     * The user may request a callback when the struct can be safely
     * freed.
     */
    if ( vmi->event_callback ) {
        if (!g_hash_table_lookup(vmi->clear_events, &event)) {
            g_hash_table_insert(vmi->clear_events,
                                g_memdup(&event, sizeof(void*)),
                                free_routine);
            return VMI_SUCCESS;
        }

        /* Event was already requested to be cleared and we haven't
         * got around to actually do it yet. */
        dbprint(VMI_DEBUG_EVENTS, "Event was already queued for clearing.\n");
        return VMI_FAILURE;
    }

    switch (event->type)
    {
    case VMI_EVENT_SINGLESTEP:
        rc = clear_singlestep_event(vmi, event);
        break;
    case VMI_EVENT_REGISTER:
        rc = clear_reg_event(vmi, event);
        break;
    case VMI_EVENT_INTERRUPT:
        rc = clear_interrupt_event(vmi, event);
        break;
    case VMI_EVENT_MEMORY:
        rc = clear_mem_event(vmi, event);
        break;
    case VMI_EVENT_GUEST_REQUEST:
        rc = clear_guest_requested_event(vmi, event);
        break;
    case VMI_EVENT_CPUID:
        rc = clear_cpuid_event(vmi, event);
        break;
    case VMI_EVENT_DEBUG_EXCEPTION:
        rc = clear_debug_event(vmi, event);
        break;
    default:
        dbprint(VMI_DEBUG_EVENTS, "Cannot clear unknown event: %d\n", event->type);
        rc = VMI_FAILURE;
    }

    if ( free_routine )
        free_routine(event, rc);

    return rc;
}

status_t vmi_step_event(vmi_instance_t vmi, vmi_event_t *event,
        uint32_t vcpu_id, uint64_t steps, event_callback_t cb)
{
    status_t rc = VMI_FAILURE;
    bool need_new_ss = 1;

    if (vcpu_id > vmi->num_vcpus)
    {
        dbprint(VMI_DEBUG_EVENTS, "The vCPU ID specified does not exist!\n");
        goto done;
    }

    if(NULL != vmi_get_singlestep_event(vmi, vcpu_id))
    {
        if(!vmi->step_vcpus[vcpu_id])
        {
            dbprint(VMI_DEBUG_EVENTS, "Can't step event, user-defined single-step is already enabled on vCPU %u\n", event->vcpu_id);
            goto done;
        }
        else
        {
            // No need to register new singlestep event, its already in place
            need_new_ss = 0;
        }
    }

    if(0 == steps) {
        dbprint(VMI_DEBUG_EVENTS, "Minimum number of steps is 1!\n");
        goto done;
    }

    if(need_new_ss) {
        // setup single step event to re-register the event
        vmi_event_t *single_event = g_malloc0(sizeof(vmi_event_t));
        SETUP_SINGLESTEP_EVENT(single_event, 0, step_and_reg_events, 1);
        SET_VCPU_SINGLESTEP(single_event->ss_event, vcpu_id);

        if(VMI_FAILURE == register_singlestep_event(vmi, single_event))
        {
            free(single_event);
            goto done;
        }
    }

    // save the event into the queue using the wrapper
    step_and_reg_event_wrapper_t *wrap = g_malloc0(sizeof(step_and_reg_event_wrapper_t));
    wrap->event = event;
    wrap->vcpu_id = vcpu_id;
    wrap->steps = steps;
    wrap->cb = cb;
    vmi->step_events = g_slist_prepend(vmi->step_events, wrap);
    vmi->step_vcpus[vcpu_id]++;

    rc = VMI_SUCCESS;

done:
    return rc;
}

int vmi_are_events_pending(vmi_instance_t vmi)
{

    if (!(vmi->init_mode & VMI_INIT_EVENTS))
    {
        return -1;
    }

    return driver_are_events_pending(vmi);

}


status_t vmi_events_listen(vmi_instance_t vmi, uint32_t timeout)
{

    if (!(vmi->init_mode & VMI_INIT_EVENTS))
    {
        return VMI_FAILURE;
    }

    return driver_events_listen(vmi, timeout);
}

status_t vmi_event_listener_required(vmi_instance_t vmi, int required)
{

    if ( required )
        vmi->event_listener_required = 1;
    else
        vmi->event_listener_required = 0;

    return VMI_SUCCESS;
}

vmi_event_t *vmi_get_singlestep_event(vmi_instance_t vmi, uint32_t vcpu)
{
    return g_hash_table_lookup(vmi->ss_events, &vcpu);
}

status_t vmi_stop_single_step_vcpu(vmi_instance_t vmi, vmi_event_t* event,
    uint32_t vcpu)
{

    if (!(vmi->init_mode & VMI_INIT_EVENTS))
    {
        return VMI_FAILURE;
    }

    UNSET_VCPU_SINGLESTEP(event->ss_event, vcpu);
    g_hash_table_remove(vmi->ss_events, &vcpu);

    return driver_stop_single_step(vmi, vcpu);
}

status_t vmi_shutdown_single_step(vmi_instance_t vmi)
{

    if (!(vmi->init_mode & VMI_INIT_EVENTS))
    {
        return VMI_FAILURE;
    }

    if(VMI_SUCCESS == driver_shutdown_single_step(vmi))
    {
        /* Safe to destroy here because the driver has disabled single-step
         *  for all VCPUs. Library user still manages event allocation at this
         *  stage.
         * Recreate hash table for possible future use.
         */
        g_hash_table_destroy(vmi->ss_events);
        vmi->ss_events = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
        return VMI_SUCCESS;
    }
    else
    {
        return VMI_FAILURE;
    }
}

uint32_t vmi_events_version(vmi_instance_t vmi)
{
    return VMI_EVENTS_VERSION;
}

