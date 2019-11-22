/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Nasser Salim (njsalim@sandia.gov)
 * Author: Steven Maresca (steve@zentific.com)
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/slat.h>

#include <xenctrl.h>

#define PAGE_SIZE 1 << 12

reg_t cr3;
vmi_event_t cr3_event;
vmi_event_t msr_syscall_lm_event;
vmi_event_t msr_syscall_compat_event;
vmi_event_t msr_syscall_sysenter_event;

vmi_event_t kernel_vdso_event;
vmi_event_t kernel_vsyscall_event;
vmi_event_t kernel_sysenter_target_event;

static unsigned long long count;

void print_event(vmi_event_t event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
           (event.mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event.mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
           (event.mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
           event.mem_event.gfn,
           event.mem_event.offset,
           event.mem_event.gla,
           event.vcpu_id
          );
}


/* MSR registers used to hold system calls in x86_64. Note that compat mode is
 *  used in concert with long mode for certain system calls.
 *  e.g. in 3.2.0 ioctl, getrlimit, etc. (see /usr/include/asm-generic/unistd.h)
 * MSR_STAR     -    legacy mode SYSCALL target (not addressed here)
 * MSR_LSTAR    -    long mode SYSCALL target
 * MSR_CSTAR    -    compat mode SYSCALL target
 *
 * Note that modern code tends to employ the sysenter and/or vDSO mechanisms for
 *    performance reasons.
 */

event_response_t msr_syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t syscall_compat_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t vsyscall_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t ia32_sysenter_target_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t syscall_lm_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}

event_response_t cr3_all_tasks_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    count++;
    return 0;
}

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = NULL;
    status_t status = VMI_SUCCESS;

    struct sigaction act;

    reg_t lstar = 0;
    addr_t phys_lstar = 0;
    reg_t cstar = 0;
    addr_t phys_cstar = 0;
    reg_t sysenter_ip = 0;
    addr_t phys_sysenter_ip = 0;

    addr_t ia32_sysenter_target = 0;
    addr_t phys_ia32_sysenter_target = 0;
    addr_t vsyscall = 0;
    addr_t phys_vsyscall = 0;

    char *name = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: events_example <name of VM>\n");
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    /* Configure an event to track when the process is running.
     * (The CR3 register is updated on task context switch, allowing
     *  us to follow as various tasks are scheduled and run upon the CPU)
     */
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_all_tasks_callback;

    /* Observe only write events to the given register.
     *   NOTE: read events are unsupported at this time.
     */
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    // Setup a default event for tracking memory at the syscall handler.
    /*memset(&msr_syscall_sysenter_event, 0, sizeof(vmi_event_t));
    msr_syscall_sysenter_event.version = VMI_EVENTS_VERSION;
    msr_syscall_sysenter_event.type = VMI_EVENT_MEMORY;
    msr_syscall_sysenter_event.mem_event.gfn = phys_sysenter_ip >> 12;
    msr_syscall_sysenter_event.mem_event.in_access = VMI_MEMACCESS_X;
    msr_syscall_sysenter_event.callback=msr_syscall_sysenter_cb;

    memset(&msr_syscall_lm_event, 0, sizeof(vmi_event_t));
    msr_syscall_lm_event.version = VMI_EVENTS_VERSION;
    msr_syscall_lm_event.type = VMI_EVENT_MEMORY;
    msr_syscall_lm_event.mem_event.gfn = phys_lstar >> 12;
    msr_syscall_lm_event.mem_event.in_access = VMI_MEMACCESS_X;
    msr_syscall_lm_event.callback=syscall_lm_cb;

    memset(&kernel_sysenter_target_event, 0, sizeof(vmi_event_t));
    kernel_sysenter_target_event.version = VMI_EVENTS_VERSION;
    kernel_sysenter_target_event.type = VMI_EVENT_MEMORY;
    kernel_sysenter_target_event.mem_event.gfn = phys_ia32_sysenter_target >> 12;
    kernel_sysenter_target_event.mem_event.in_access = VMI_MEMACCESS_X;
    kernel_sysenter_target_event.callback=ia32_sysenter_target_cb;

    memset(&kernel_vsyscall_event, 0, sizeof(vmi_event_t));
    kernel_vsyscall_event.version = VMI_EVENTS_VERSION;
    kernel_vsyscall_event.type = VMI_EVENT_MEMORY;
    kernel_vsyscall_event.mem_event.gfn = phys_vsyscall >> 12;
    kernel_vsyscall_event.mem_event.in_access = VMI_MEMACCESS_X;
    kernel_vsyscall_event.callback=vsyscall_cb;*/

    addr_t test, test_pa;
    vmi_translate_ksym2v(vmi, "KeBugCheck2", &test);
    vmi_translate_kv2p(vmi, test, &test_pa);

    printf("Bugcheck @ 0x%lx -> 0x%lx\n", test, test_pa);

    if ( VMI_FAILURE == vmi_register_event(vmi, &cr3_event) )
        printf("Failed to register CR3 event\n");
    /*if ( phys_sysenter_ip && VMI_FAILURE == vmi_register_event(vmi, &msr_syscall_sysenter_event) )
        printf("Failed to register memory event on MSR_SYSENTER_IP page\n");
    if ( phys_lstar && VMI_FAILURE == vmi_register_event(vmi, &msr_syscall_lm_event) )
        printf("Failed to register memory event on MSR_LSTAR page\n");
    if ( phys_ia32_sysenter_target && VMI_FAILURE == vmi_register_event(vmi, &kernel_sysenter_target_event) )
        printf("Failed to register memory event on ia32_sysenter_target page\n");
    if ( phys_vsyscall && VMI_FAILURE == vmi_register_event(vmi, &kernel_vsyscall_event) )
        printf("Failed to register memory event on vsyscall page\n");*/

    vmi_pause_vm(vmi);

    vmi_slat_set_domain_state(vmi, 1);
    uint16_t altp2m_idx;
    vmi_slat_create(vmi, &altp2m_idx);

    uint8_t buffer[4096];
    vmi_read_va(vmi, test, 0, 4096, &buffer, NULL);

    xc_interface *xch = xc_interface_open(0,0,0);

    xen_pfn_t max, new_gfn;

    xc_domain_maximum_gpfn(xch, vmi_get_vmid(vmi), &max);

    new_gfn = ++max;

    xc_domain_populate_physmap_exact(xch, vmi_get_vmid(vmi), 1, 0, 0, &new_gfn);

    printf("New: %lu 0x%lx\n", new_gfn, new_gfn<<12);
    vmi_write_pa(vmi, new_gfn<<12, 4096, &buffer, NULL);

    printf("Altp2m id: %u\n", altp2m_idx);

    vmi_slat_change_gfn(vmi, altp2m_idx, test_pa>>12, new_gfn);

    vmi_slat_switch(vmi, altp2m_idx);

    vmi_resume_vm(vmi);

    while (!interrupted) {
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

    vmi_pause_vm(vmi);
    //status = vmi_events_listen(vmi,0);

    printf("Finished with test.\n");

    vmi_slat_switch(vmi, 0);
    vmi_slat_destroy(vmi, altp2m_idx);
    vmi_slat_set_domain_state(vmi, 0);

    xc_domain_decrease_reservation_exact(xch, vmi_get_vmid(vmi), 1, 0, &new_gfn);
    //vmi_clear_event(vmi, &cr3_event, NULL);

    vmi_resume_vm(vmi);

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    xc_interface_close(xch);

    printf("%lu\n", count);

    return 0;
}
