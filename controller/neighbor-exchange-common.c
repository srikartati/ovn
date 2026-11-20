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

#include "neighbor-exchange.h"
#include "openvswitch/dynamic-string.h"
#include "ovn-util.h"
#include "packets.h"
#include "unixctl.h"

static uint32_t evpn_remote_vtep_hash(const struct in6_addr *ip,
                                      uint16_t port, uint32_t vni);
static uint32_t evpn_static_entry_hash(const struct eth_addr *mac,
                                       const struct in6_addr *ip,
                                       uint32_t vni, uint32_t nh_id);

void
evpn_remote_vteps_clear(struct hmap *remote_vteps)
{
    struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH_POP (vtep, hmap_node, remote_vteps) {
        free(vtep);
    }
}

void
evpn_remote_vtep_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *data_)
{
    struct hmap *remote_vteps = data_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH (vtep, hmap_node, remote_vteps) {
        ds_put_cstr(&ds, "IP: ");
        ipv6_format_mapped(&vtep->ip, &ds);
        ds_put_format(&ds, ", port: %"PRIu16", vni: %"PRIu32"\n",
                      vtep->port, vtep->vni);
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

void
evpn_static_entries_clear(struct hmap *static_entries)
{
    struct evpn_static_entry *e;
    HMAP_FOR_EACH_POP (e, hmap_node, static_entries) {
        free(e);
    }
}

void
evpn_remote_vtep_add(struct hmap *remote_vteps, struct in6_addr ip,
                     uint16_t port, uint32_t vni)
{
    struct evpn_remote_vtep *vtep = xmalloc(sizeof *vtep);
    *vtep = (struct evpn_remote_vtep) {
        .ip = ip,
        .port = port,
        .vni = vni,
    };

    hmap_insert(remote_vteps, &vtep->hmap_node,
                evpn_remote_vtep_hash(&ip, port, vni));
}

struct evpn_remote_vtep *
evpn_remote_vtep_find(const struct hmap *remote_vteps,
                      const struct in6_addr *ip,
                      uint16_t port, uint32_t vni)
{
    uint32_t hash = evpn_remote_vtep_hash(ip, port, vni);

    struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH_WITH_HASH (vtep, hmap_node, hash, remote_vteps) {
        if (ipv6_addr_equals(&vtep->ip, ip) &&
            vtep->port == port && vtep->vni == vni) {
            return vtep;
        }
    }

    return NULL;
}

static uint32_t
evpn_remote_vtep_hash(const struct in6_addr *ip, uint16_t port,
                      uint32_t vni)
{
    uint32_t hash = 0;
    hash = hash_add_in6_addr(hash, ip);
    hash = hash_add(hash, port);
    hash = hash_add(hash, vni);

    return hash_finish(hash, 14);
}

void
evpn_static_entry_add(struct hmap *static_entries, struct eth_addr mac,
                      struct in6_addr ip, uint32_t vni, uint32_t nh_id)
{
    struct evpn_static_entry *e = xmalloc(sizeof *e);
    *e = (struct evpn_static_entry) {
        .mac = mac,
        .ip = ip,
        .vni = vni,
        .nh_id = nh_id,
    };

    hmap_insert(static_entries, &e->hmap_node,
                evpn_static_entry_hash(&mac, &ip, vni, nh_id));
}

struct evpn_static_entry *
evpn_static_entry_find(const struct hmap *static_entries, struct eth_addr mac,
                       struct in6_addr ip, uint32_t vni, uint32_t nh_id)
{
    uint32_t hash = evpn_static_entry_hash(&mac, &ip, vni, nh_id);

    struct evpn_static_entry *e;
    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, hash, static_entries) {
        if (eth_addr_equals(e->mac, mac) &&
            ipv6_addr_equals(&e->ip, &ip) &&
            e->vni == vni &&
            e->nh_id == nh_id) {
            return e;
        }
    }

    return NULL;
}

static uint32_t
evpn_static_entry_hash(const struct eth_addr *mac, const struct in6_addr *ip,
                       uint32_t vni, uint32_t nh_id)
{
    uint32_t hash = 0;
    hash = hash_bytes(mac, sizeof *mac, hash);
    hash = hash_add_in6_addr(hash, ip);
    hash = hash_add(hash, vni);
    hash = hash_add(hash, nh_id);

    return hash_finish(hash, 30);
}

/* Adds to 'dst' a copy of each entry of 'src' that 'dst' lacks. */
void
evpn_remote_vteps_merge(struct hmap *dst, const struct hmap *src)
{
    const struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH (vtep, hmap_node, src) {
        if (!evpn_remote_vtep_find(dst, &vtep->ip, vtep->port, vtep->vni)) {
            evpn_remote_vtep_add(dst, vtep->ip, vtep->port, vtep->vni);
        }
    }
}

void
evpn_static_entries_merge(struct hmap *dst, const struct hmap *src)
{
    const struct evpn_static_entry *e;
    HMAP_FOR_EACH (e, hmap_node, src) {
        if (!evpn_static_entry_find(dst, e->mac, e->ip, e->vni, e->nh_id)) {
            evpn_static_entry_add(dst, e->mac, e->ip, e->vni, e->nh_id);
        }
    }
}
