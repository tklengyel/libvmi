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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>

#define PAGE_SIZE 1 << 12

reg_t cr3;
vmi_event_t cr3_event;
vmi_event_t msr_syscall_lm_event;
vmi_event_t msr_syscall_compat_event;
vmi_event_t msr_syscall_sysenter_event;

vmi_event_t kernel_vdso_event;
vmi_event_t kernel_vsyscall_event;
vmi_event_t kernel_sysenter_target_event;

void print_event(vmi_event_t event){
    printf("PAGE %lx ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %lu)\n",
        event.mem_event.page,
        (event.mem_event.out_access == VMI_MEM_R) ? 'r' : '-',
        (event.mem_event.out_access == VMI_MEM_W) ? 'w' : '-',
        (event.mem_event.out_access == VMI_MEM_X) ? 'x' : '-',
        event.mem_event.gfn,
        event.mem_event.offset,
        event.mem_event.gla,
	event.vcpu_id
    );
}
    

/* MSR registers used to hold system calls in x86_64. Note that compat mode is
 *	used in concert with long mode for certain system calls.
 *	e.g. in 3.2.0 ioctl, getrlimit, etc. (see /usr/include/asm-generic/unistd.h)
 * MSR_STAR     -    legacy mode SYSCALL target (not addressed here)
 * MSR_LSTAR    -    long mode SYSCALL target 
 * MSR_CSTAR    -    compat mode SYSCALL target 
 * 
 * Note that modern code tends to employ the sysenter and/or vDSO mechanisms for 
 *    performance reasons.
 */

void msr_syscall_sysenter_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);

    print_event(*event);   
 
    vmi_clear_event(vmi, &msr_syscall_sysenter_event);
}

void syscall_compat_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);
    
    print_event(*event);   
    
    vmi_clear_event(vmi, &msr_syscall_compat_event);
}

void vsyscall_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);
    
    print_event(*event);   
   
    vmi_clear_event(vmi, &kernel_vsyscall_event);
}

void ia32_sysenter_target_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);
    
    print_event(*event);   
   
    vmi_clear_event(vmi, &kernel_sysenter_target_event);
}

void syscall_lm_cb(vmi_instance_t vmi, vmi_event_t *event){
    reg_t rdi, rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);

    printf("Syscall happened: RAX(syscall#)=%u RDI(1st argument)=%u\n", (unsigned int)rax, (unsigned int)rdi);
    
    print_event(*event);   
   
    vmi_clear_event(vmi, &msr_syscall_lm_event);
}

void cr3_one_task_callback(vmi_instance_t vmi, vmi_event_t *event){

    int pid = vmi_dtb_to_pid(vmi, event->reg_event.value);

    printf("one_task callback\n");
    if(event->reg_event.value == cr3){
        printf("My process (PID %i) is executing on vcpu %lu\n", pid, event->vcpu_id);
        
        msr_syscall_sysenter_event.mem_event.in_access = VMI_MEM_X;
        kernel_sysenter_target_event.mem_event.in_access = VMI_MEM_X;
        kernel_vsyscall_event.mem_event.in_access = VMI_MEM_X;

        if(vmi_handle_event(vmi, &msr_syscall_sysenter_event, msr_syscall_sysenter_cb) == VMI_FAILURE)
            fprintf(stderr, "Could not install sysenter syscall handler.\n");
        if(vmi_handle_event(vmi, &kernel_sysenter_target_event, ia32_sysenter_target_cb) == VMI_FAILURE)
            fprintf(stderr, "Could not install sysenter syscall handler.\n");
        if(vmi_handle_event(vmi, &kernel_vsyscall_event, vsyscall_cb) == VMI_FAILURE)
            fprintf(stderr, "Could not install sysenter syscall handler.\n");
    }
    else{
        printf("PID %i is executing, not my process!\n", pid);
        vmi_clear_event(vmi, &msr_syscall_sysenter_event);
    }
}

void cr3_all_tasks_callback(vmi_instance_t vmi, vmi_event_t *event){
    int pid = vmi_dtb_to_pid(vmi, event->reg_event.value);
    printf("PID %i with CR3=%lx executing on vcpu %lu.\n", pid, event->reg_event.value, event->vcpu_id);

	msr_syscall_sysenter_event.mem_event.in_access = VMI_MEM_X;

	if(vmi_handle_event(vmi, &msr_syscall_sysenter_event, msr_syscall_sysenter_cb) == VMI_FAILURE)
	    fprintf(stderr, "Could not install sysenter syscall handler.\n");
	vmi_clear_event(vmi, &msr_syscall_sysenter_event);
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi;

    reg_t lstar;
    addr_t phys_lstar;
    reg_t cstar;
    addr_t phys_cstar;
    reg_t sysenter_ip;
    addr_t phys_sysenter_ip;
    
    addr_t ia32_sysenter_target;
    addr_t phys_ia32_sysenter_target;
    addr_t vsyscall;
    addr_t phys_vsyscall;

    char *name = NULL;
    int i=50;
    int pid=-1;

    if(argc < 2){
        fprintf(stderr, "Usage: events_example <name of VM> <PID of process to track {optional}>\n");
        exit(1);
    }
   
    // Arg 1 is the VM name.
    name = argv[1];
    
    // Arg 2 is the pid of the process to track.
    if(argc == 3)
        pid = (int) strtoul(argv[2], NULL, 0);

    // Initialize the libvmi library.
    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        return 1;
    }
    else{
        printf("LibVMI init succeeded!\n");
    }

    // Get the cr3 for this process.
    cr3 = vmi_pid_to_dtb(vmi, pid);
    printf("CR3 for process (%d) == %llx\n", pid, (unsigned long long)cr3);

    // Get the value of lstar and cstar for the system.
    // NOTE: all vCPUs have the same value for these registers
    vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);
    vmi_get_vcpureg(vmi, &cstar, MSR_CSTAR, 0);
    vmi_get_vcpureg(vmi, &sysenter_ip, SYSENTER_EIP, 0);
    printf("vcpu 0 MSR_LSTAR == %llx\n", (unsigned long long)lstar);
    printf("vcpu 0 MSR_CSTAR == %llx\n", (unsigned long long)cstar);
    printf("vcpu 0 MSR_SYSENTER_IP == %llx\n", (unsigned long long)sysenter_ip);

    ia32_sysenter_target = vmi_translate_ksym2v(vmi, "ia32_sysenter_target");
    printf("ksym ia32_sysenter_target == %llx\n", (unsigned long long)ia32_sysenter_target);

    vsyscall = 0xffffffffff600000;

    // Translate to a physical address.
    phys_lstar= vmi_translate_kv2p(vmi, lstar);
    printf("Physical LSTAR == %llx\n", (unsigned long long)phys_lstar);
    
    phys_cstar= vmi_translate_kv2p(vmi, cstar);
    printf("Physical CSTAR == %llx\n", (unsigned long long)phys_cstar);
    
    phys_sysenter_ip= vmi_translate_kv2p(vmi, sysenter_ip);
    printf("Physical SYSENTER_IP == %llx\n", (unsigned long long)phys_sysenter_ip);

    phys_ia32_sysenter_target = vmi_translate_kv2p(vmi,ia32_sysenter_target);
    printf("Physical ia32_sysenter_target == %llx\n", (unsigned long long)ia32_sysenter_target);
    phys_vsyscall = vmi_translate_kv2p(vmi,vsyscall);
    printf("Physical phys_vsyscall == %llx\n", (unsigned long long)phys_vsyscall);

    
    // Get only the page that the handler starts.
    phys_lstar >>= 12;
    printf("LSTAR Physical PFN == %llx\n", (unsigned long long)phys_lstar);
    phys_cstar >>= 12;
    printf("CSTAR Physical PFN == %llx\n", (unsigned long long)phys_cstar);
    phys_sysenter_ip >>= 12;
    printf("SYSENTER_IP Physical PFN == %llx\n", (unsigned long long)phys_sysenter_ip);
    phys_vsyscall >>= 12;
    printf("phys_vsyscall Physical PFN == %llx\n", (unsigned long long)phys_vsyscall);
    phys_ia32_sysenter_target >>= 12;
    printf("phys_ia32_sysenter_target Physical PFN == %llx\n", (unsigned long long)phys_ia32_sysenter_target);

    // Setup cr3 event to track when the process is running.
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.type = VMI_REGISTER_EVENT;
    cr3_event.reg_event.reg = CR3;
 //   cr3_event.reg_event.onchange =1;
    //cr3_event.reg_event.async =1;
    cr3_event.reg_event.equal = cr3;
    cr3_event.reg_event.in_access = VMI_REG_W;

    if(pid == -1){
        vmi_handle_event(vmi, &cr3_event, cr3_all_tasks_callback);
    } else {
        vmi_handle_event(vmi, &cr3_event, cr3_one_task_callback);
    }

    // Setup a default event for tracking memory at the syscall handler.
    // But don't install it; that will be done by the cr3 handler.
    memset(&msr_syscall_sysenter_event, 0, sizeof(vmi_event_t));
    msr_syscall_sysenter_event.type = VMI_MEMORY_EVENT;
    msr_syscall_sysenter_event.mem_event.page = phys_sysenter_ip;
    msr_syscall_sysenter_event.mem_event.npages = 1;

    memset(&kernel_sysenter_target_event, 0, sizeof(vmi_event_t));
    kernel_sysenter_target_event.type = VMI_MEMORY_EVENT;
    kernel_sysenter_target_event.mem_event.page = phys_ia32_sysenter_target;
    kernel_sysenter_target_event.mem_event.npages = 1;

    memset(&kernel_vsyscall_event, 0, sizeof(vmi_event_t));
    kernel_vsyscall_event.type = VMI_MEMORY_EVENT;
    kernel_vsyscall_event.mem_event.page = phys_vsyscall;
    kernel_vsyscall_event.mem_event.npages = 1;

   
    while(i--){
        printf("Waiting for events...\n");
        vmi_events_listen(vmi,500);
    }
    printf("Finished with test.\n");

leave:
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;
}
