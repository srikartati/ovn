/*
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

#include "datapath-sync.h"
#include "en-datapath-logical-switch.h"
#include "en-evpn-static-neighbor-sync.h"
#include "hash.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "packets.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(en_evpn_static_neighbor_sync);

struct vni_switch {
    struct hmap_node hmap_node;
    uint32_t vni;
    const struct sbrec_datapath_binding *sb_dp;
    bool duplicate;
};

/* One desired SB row; strings are normalized, 'mac' NULL if unset. */
struct evpn_static_neighbor {
    struct hmap_node hmap_node;
    const struct sbrec_datapath_binding *sb_dp;
    char *mac;
    char *vtep_ip;
    int64_t vtep_port;
};

static uint32_t
hash_opt_str(const char *s, uint32_t basis)
{
    return s ? hash_string(s, basis) : hash_int(0, basis);
}

static uint32_t
evpn_static_neighbor_hash(const struct sbrec_datapath_binding *sb_dp,
                          const char *mac, const char *vtep_ip,
                          int64_t vtep_port)
{
    uint32_t hash = uuid_hash(&sb_dp->header_.uuid);
    hash = hash_opt_str(mac, hash);
    hash = hash_string(vtep_ip, hash);
    return hash_uint64_basis(vtep_port, hash);
}

static struct evpn_static_neighbor *
evpn_static_neighbor_find(const struct hmap *map,
                          const struct sbrec_datapath_binding *sb_dp,
                          const char *mac, const char *vtep_ip,
                          int64_t vtep_port)
{
    uint32_t hash = evpn_static_neighbor_hash(sb_dp, mac, vtep_ip,
                                              vtep_port);
    struct evpn_static_neighbor *e;
    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, hash, map) {
        if (e->sb_dp == sb_dp && nullable_string_is_equal(e->mac, mac) &&
            !strcmp(e->vtep_ip, vtep_ip) &&
            e->vtep_port == vtep_port) {
            return e;
        }
    }
    return NULL;
}

static void
evpn_static_neighbor_destroy(struct evpn_static_neighbor *e)
{
    free(e->mac);
    free(e->vtep_ip);
    free(e);
}

static struct vni_switch *
vni_switch_find(const struct hmap *map, uint32_t vni)
{
    struct vni_switch *vs;
    HMAP_FOR_EACH_WITH_HASH (vs, hmap_node, hash_int(vni, 0), map) {
        if (vs->vni == vni) {
            return vs;
        }
    }
    return NULL;
}

static void
build_vni_switch_map(const struct ovn_synced_logical_switch_map *switches,
                     struct hmap *map)
{
    const struct ovn_synced_logical_switch *ls;
    HMAP_FOR_EACH (ls, hmap_node, &switches->synced_switches) {
        int64_t vni = ovn_smap_get_llong(&ls->nb->other_config,
                                         "dynamic-routing-vni", -1);
        if (!ovn_is_valid_vni(vni)) {
            continue;
        }

        struct vni_switch *vs = vni_switch_find(map, vni);
        if (vs) {
            vs->duplicate = true;
            continue;
        }
        vs = xzalloc(sizeof *vs);
        vs->vni = vni;
        vs->sb_dp = ls->sdp->sb_dp;
        hmap_insert(map, &vs->hmap_node, hash_int(vni, 0));
    }
}

static struct evpn_static_neighbor *
parse_nb_row(const struct nbrec_evpn_static_neighbor *nb,
             const struct sbrec_datapath_binding *sb_dp)
{
    struct in6_addr vtep;
    bool error = !ip46_parse(nb->vtep_ip, &vtep);
    struct evpn_static_neighbor *e = xzalloc(sizeof *e);
    e->sb_dp = sb_dp;
    e->vtep_port = nb->vtep_port ? *nb->vtep_port : 0;

    if (!error) {
        char buf[INET6_ADDRSTRLEN];
        e->vtep_ip = xstrdup(ipv6_string_mapped(buf, &vtep));
    }
    if (nb->mac) {
        struct eth_addr ea;
        if (eth_addr_from_string(nb->mac, &ea) && !eth_addr_is_zero(ea)) {
            e->mac = xasprintf(ETH_ADDR_FMT, ETH_ADDR_ARGS(ea));
        } else {
            error = true;
        }
    }

    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Ignoring invalid EVPN_Static_Neighbor "UUID_FMT,
                     UUID_ARGS(&nb->header_.uuid));
        evpn_static_neighbor_destroy(e);
        return NULL;
    }
    return e;
}

void *
en_evpn_static_neighbor_sync_init(struct engine_node *node OVS_UNUSED,
                                  struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_evpn_static_neighbor_sync_cleanup(void *data OVS_UNUSED)
{
}

enum engine_node_state
en_evpn_static_neighbor_sync_run(struct engine_node *node,
                                 void *data OVS_UNUSED)
{
    const struct nbrec_evpn_static_neighbor_table *nb_table =
        EN_OVSDB_GET(engine_get_input("NB_evpn_static_neighbor", node));
    const struct sbrec_evpn_static_neighbor_table *sb_table =
        EN_OVSDB_GET(engine_get_input("SB_evpn_static_neighbor", node));
    const struct ovn_synced_logical_switch_map *switches =
        engine_get_input_data("datapath_synced_logical_switch", node);
    const struct engine_context *eng_ctx = engine_get_context();

    struct hmap vni_map = HMAP_INITIALIZER(&vni_map);
    build_vni_switch_map(switches, &vni_map);

    struct hmap desired = HMAP_INITIALIZER(&desired);
    const struct nbrec_evpn_static_neighbor *nb;
    NBREC_EVPN_STATIC_NEIGHBOR_TABLE_FOR_EACH (nb, nb_table) {
        struct vni_switch *vs = vni_switch_find(&vni_map, nb->vni);
        if (!vs || vs->duplicate) {
            continue;
        }

        struct evpn_static_neighbor *e = parse_nb_row(nb, vs->sb_dp);
        if (!e) {
            continue;
        }
        if (evpn_static_neighbor_find(&desired, e->sb_dp, e->mac,
                                      e->vtep_ip, e->vtep_port)) {
            evpn_static_neighbor_destroy(e);
            continue;
        }
        hmap_insert(&desired, &e->hmap_node,
                    evpn_static_neighbor_hash(e->sb_dp, e->mac,
                                              e->vtep_ip, e->vtep_port));
    }

    const struct sbrec_evpn_static_neighbor *sb;
    SBREC_EVPN_STATIC_NEIGHBOR_TABLE_FOR_EACH_SAFE (sb, sb_table) {
        int64_t port = sb->vtep_port ? *sb->vtep_port : 0;
        struct evpn_static_neighbor *e =
            sb->datapath
            ? evpn_static_neighbor_find(&desired, sb->datapath, sb->mac,
                                        sb->vtep_ip, port)
            : NULL;
        if (e) {
            hmap_remove(&desired, &e->hmap_node);
            evpn_static_neighbor_destroy(e);
        } else {
            sbrec_evpn_static_neighbor_delete(sb);
        }
    }

    struct evpn_static_neighbor *e;
    HMAP_FOR_EACH_POP (e, hmap_node, &desired) {
        sb = sbrec_evpn_static_neighbor_insert(eng_ctx->ovnsb_idl_txn);
        sbrec_evpn_static_neighbor_set_datapath(sb, e->sb_dp);
        sbrec_evpn_static_neighbor_set_mac(sb, e->mac);
        sbrec_evpn_static_neighbor_set_vtep_ip(sb, e->vtep_ip);
        if (e->vtep_port) {
            sbrec_evpn_static_neighbor_set_vtep_port(sb, &e->vtep_port, 1);
        }
        evpn_static_neighbor_destroy(e);
    }
    hmap_destroy(&desired);

    struct vni_switch *vs;
    HMAP_FOR_EACH_POP (vs, hmap_node, &vni_map) {
        free(vs);
    }
    hmap_destroy(&vni_map);

    return EN_UPDATED;
}

enum engine_input_handler_result
evpn_static_neighbor_sync_logical_switch_handler(struct engine_node *node,
                                                 void *data OVS_UNUSED)
{
    const struct ovn_synced_logical_switch_map *switches =
        engine_get_input_data("datapath_synced_logical_switch", node);

    /* No tracked changes means the input was recomputed. */
    if (!hmapx_is_empty(&switches->new) ||
        !hmapx_is_empty(&switches->deleted) ||
        hmapx_is_empty(&switches->updated)) {
        return EN_UNHANDLED;
    }

    /* Only an other_config change can move a VNI between switches. */
    const struct hmapx_node *hn;
    HMAPX_FOR_EACH (hn, &switches->updated) {
        const struct ovn_synced_logical_switch *ls = hn->data;
        if (nbrec_logical_switch_is_updated(
                ls->nb, NBREC_LOGICAL_SWITCH_COL_OTHER_CONFIG)) {
            return EN_UNHANDLED;
        }
    }
    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
northd_output_evpn_static_neighbor_sync_handler(
    struct engine_node *node OVS_UNUSED, void *data OVS_UNUSED)
{
    return EN_HANDLED_UPDATED;
}
