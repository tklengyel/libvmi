/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Sergey Kovalev (valor@list.ru)
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

#define LIBVMI_EXTRA_JSON

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <glib.h>
#include <signal.h>
#include <unistd.h>

vmi_instance_t vmi;
vmi_event_t cr3_event;

int borks = 0;

void clean_up(void)
{
    //if ( borks == 1 )
        vmi_resume_vm(vmi);
//    vmi_resume_vm(vmi);
    vmi_destroy(vmi);
    printf("Done. Sleep for a minute\n");
    sleep(60);
}

void sigint_handler()
{
    clean_up();
    exit(1);
}

event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("borks %d: %lu\n", event->vcpu_id, event->reg_event.value);
    //if ( !borks )
    {
        vmi_pause_vm(vmi);
        //vmi_clear_event(vmi, event, NULL);
    }
    borks++;
    return VMI_EVENT_RESPONSE_NONE;
}

void show_usage(char *arg0)
{
    printf("Usage: %s name|domid <domain name|domain id>\n", arg0);
}

int main(int argc, char **argv)
{
    vmi_mode_t mode;
    int rc = 1;

    void *domain;
    uint64_t domid = VMI_INVALID_DOMID;
    uint64_t init_flags = 0;

    char *rekall_profile = NULL;
    char c;

    while ((c = getopt (argc, argv, "")) != -1)
      switch (c) {
    default:
      printf("xxx\n");
      show_usage(argv[0]);
      return 1;
      }

    if (argc - optind != 2) {
        show_usage(argv[0]);
    return 1;
    }

    if (strcmp(argv[optind],"name")==0) {
        domain = (void*)argv[optind+1];
        init_flags |= VMI_INIT_DOMAINNAME;
    } else if (strcmp(argv[optind],"domid")==0) {
        domid = strtoull(argv[optind+1], NULL, 0);
        domain = (void*)&domid;
        init_flags |= VMI_INIT_DOMAINID;
    } else {
        printf("You have to specify either name or domid!\n");
    show_usage(argv[0]);
        return 1;
    }

    if (VMI_FAILURE == vmi_get_access_mode(vmi, domain, init_flags, NULL, &mode) )
        return 1;

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags | VMI_INIT_EVENTS, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    signal(SIGINT, sigint_handler);

    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_cb;

    if (VMI_FAILURE == vmi_register_event(vmi, &cr3_event)) {
        printf("Failed to register CR3 write event\n");
        goto done;
    }

    while (borks != 2) {
        vmi_resume_vm(vmi);
        borks = 0;
        if (VMI_FAILURE == vmi_events_listen(vmi, 500)) {
            printf("Failed to listen to VMI events\n");
            goto done;
        }
    }

    if ( vmi_are_events_pending(vmi) > 0 )
        vmi_events_listen(vmi, 0);

    vmi_clear_event(vmi, &cr3_event, NULL);

    rc = 0;

    /* cleanup any memory associated with the LibVMI instance */
done:
    //sleep(2);
    clean_up();
    return rc;
}

