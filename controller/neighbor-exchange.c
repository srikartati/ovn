/* Copyright (c) 2025, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <linux/neighbour.h>

#include "host-if-monitor.h"
#include "neighbor.h"
#include "neighbor-exchange.h"
#include "neighbor-exchange-netlink.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "packets.h"
#include "vec.h"

VLOG_DEFINE_THIS_MODULE(neighbor_exchange);

/* Last neighbor_exchange netlink operation. */
static int neighbor_exchange_nl_status;

#define CLEAR_NEIGHBOR_EXCHANGE_NL_STATUS() \
    do {                                    \
        neighbor_exchange_nl_status = 0;    \
    } while (0)

#define SET_NEIGHBOR_EXCHANGE_NL_STATUS(error)     \
    do {                                           \
        if (!neighbor_exchange_nl_status) {        \
            neighbor_exchange_nl_status = (error); \
            if (error) {                           \
                poll_immediate_wake();             \
            }                                      \
        }                                          \
    } while (0)

void
neighbor_exchange_run(const struct neighbor_exchange_ctx_in *n_ctx_in,
                      struct neighbor_exchange_ctx_out *n_ctx_out)
{
    struct neighbor_interface_monitor *nim;

    struct sset if_names = SSET_INITIALIZER(&if_names);
    VECTOR_FOR_EACH (n_ctx_in->monitored_interfaces, nim) {
        sset_add(&if_names, nim->if_name);
    }
    host_if_monitor_update_watches(&if_names);
    sset_destroy(&if_names);

    CLEAR_NEIGHBOR_EXCHANGE_NL_STATUS();
    VECTOR_FOR_EACH (n_ctx_in->monitored_interfaces, nim) {
        int32_t if_index = host_if_monitor_ifname_toindex(nim->if_name);

        if (!if_index) {
            continue;
        }

        struct vector received_neighbors =
            VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
        SET_NEIGHBOR_EXCHANGE_NL_STATUS(
            ne_nl_sync_neigh(nim->family, if_index, nim->type,
                             &nim->announced_neighbors, &received_neighbors)
        );

        struct ne_nl_received_neigh *ne;
        switch (nim->type) {
        case NEIGH_IFACE_BRIDGE:
            VECTOR_FOR_EACH_PTR (&received_neighbors, ne) {
                if (ne_is_valid_static_arp(ne)) {
                    if (!evpn_static_entry_find(n_ctx_out->static_arps,
                                                ne->lladdr, ne->addr,
                                                nim->vni, 0)) {
                        evpn_static_entry_add(n_ctx_out->static_arps,
                                              ne->lladdr, ne->addr,
                                              nim->vni, 0);
                    }
                }
            }
            break;
        case NEIGH_IFACE_VXLAN:
            VECTOR_FOR_EACH_PTR (&received_neighbors, ne) {
                if (ne_is_valid_remote_vtep(ne)) {
                    uint16_t port = ne->port ? ne->port : DEFAULT_VXLAN_PORT;
                    if (!evpn_remote_vtep_find(n_ctx_out->remote_vteps,
                                               &ne->addr, port, nim->vni)) {
                        evpn_remote_vtep_add(n_ctx_out->remote_vteps, ne->addr,
                                             port, nim->vni);
                    }
                }

                if (ne_is_valid_static_fdb(ne)) {
                    if (!evpn_static_entry_find(n_ctx_out->static_fdbs,
                                                ne->lladdr, ne->addr,
                                                nim->vni, ne->nh_id)) {
                        evpn_static_entry_add(n_ctx_out->static_fdbs,
                                              ne->lladdr, ne->addr,
                                              nim->vni, ne->nh_id);
                    }
                }
            }
            break;
        case NEIGH_IFACE_LOOPBACK:
            /* No learning from the loopback interface required. */
            break;
        case NEIGH_IFACE_UNSPECIFIED:
            OVS_NOT_REACHED();
        }

        vector_push(n_ctx_out->neighbor_table_watches, &if_index);
        vector_destroy(&received_neighbors);
    }
}

int
neighbor_exchange_status_run(void)
{
    return neighbor_exchange_nl_status;
}
