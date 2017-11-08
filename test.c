#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/bridge.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>

/* Notes
 *
 *   - assigning an IPv4 address to an interface results in a very quick
 *     call to the NEW ADDRESS callback. However, a new IPv6 assignment
 *     incurs an 0.5 to 2 second (observed by feel, not by measure) delay,
 *     presumably while the kernel does a peer check on the address.
 */

struct nl_cache *myroutecahe = NULL;
struct nl_cache *myaddrcache = NULL;
struct nl_cache *mylinkcache = NULL;

struct state {
    const char *target;
    int found;
};

static void addrinfo(struct nl_object *obj, void *arg);

static void
myparse(struct nl_object *obj, void *arg)
{
#if DEBUG
    printf(" myparse\n");
    printf("  type: %s\n", nl_object_get_type(obj));
    char buf[1024];
    char *ret;
    ret = nl_object_attr_list(obj, buf, sizeof buf);
    printf(" ret: %p, list: %p\n", ret, buf);
    printf(" %s\n", buf);
    printf(" idattrs: %x\n", nl_object_get_id_attrs(obj));
    printf(" msgtype: %x\n", nl_object_get_msgtype(obj));
    //struct nl_object_ops *ops = nl_object_get_ops(obj);
    struct nl_cache *cache = nl_object_get_cache(obj);
    if (cache) {
        printf(" cache: %p\n", cache);
        printf("  count: %i\n", nl_cache_nitems(cache));
    }
#endif
    int islink = 0;
    if (nl_object_get_msgtype(obj) == RTM_NEWLINK) {
        printf(" New (or updated) link!\n");
        islink = 1;
    } else if (nl_object_get_msgtype(obj) == RTM_DELLINK) {
        printf(" Removed link!\n");
        islink = 1;
    } else if (nl_object_get_msgtype(obj) == RTM_NEWADDR) {
        printf(" New (or updated) address!\n");
        addrinfo(obj, NULL);
    } else if (nl_object_get_msgtype(obj) == RTM_DELADDR) {
        printf(" Removed address!\n");
        addrinfo(obj, NULL);
    }
    if (islink) {
        /* Hold your breath, cross your fingers, and cast it... */
        struct rtnl_link *link = (struct rtnl_link *)obj;
        printf("  name: %s\n", rtnl_link_get_name(link));
        printf("  type: %s\n", rtnl_link_get_type(link));
    }
#ifdef DEBUG
    printf("dump:");
    int i;
    for (i = 0; i < 80; i++) {
        if (i % 4 == 0) {
            printf("\n %x: ", i);
        }
        printf(" %02hhx", ((uint8_t*)obj)[i]);
    }
    printf("\n");
#endif
}

static void
addrinfo(struct nl_object *obj, void *arg)
{
    int type = nl_object_get_msgtype(obj);
    if (type != RTM_NEWADDR && type != RTM_DELADDR) {
        /* TODO: Error? Warning? */
        return;
    }
    struct rtnl_addr *addr = (struct rtnl_addr *)obj;
    printf("interface %3i", rtnl_addr_get_ifindex(addr));
    printf(" family %2i", rtnl_addr_get_family(addr));
    printf(" prefix %3i", rtnl_addr_get_prefixlen(addr));
    printf(" scope %3i", rtnl_addr_get_scope(addr));
    struct nl_addr *naddr = rtnl_addr_get_local(addr);
    char *repr = malloc(128);
    nl_addr2str(naddr, repr, 128);
    repr[127] = '\0'; // just in case
    printf(" repr %s", repr);
    free(repr);
    printf("\n");
}

static void
linkinfo(struct nl_object *obj, void *arg)
{
    int type = nl_object_get_msgtype(obj);
    struct state *state = arg;
    if (type == RTM_NEWLINK) {
        struct rtnl_link *link = (struct rtnl_link *)obj;
        printf(" ifindex: %3i", rtnl_link_get_ifindex(link));
        printf("  name: %-16s", rtnl_link_get_name(link));
        if (state && strcmp(state->target, rtnl_link_get_name(link)) == 0) {
            state->found = 1;
        }
        const char *type = rtnl_link_get_type(link);
        if (type) {
            printf("  type: %-11s", type);
        }
        int master = rtnl_link_get_master(link);
        if (master) {
            printf("  master: %i", master);
        }
        int32_t outns;
        int ret;
        ret = rtnl_link_get_link_netnsid(link, &outns);
        if (ret == 0) {
            printf("  nsid: %i", outns);
        }
        pid_t nspid = rtnl_link_get_ns_pid(link);
        if (nspid) {
            printf("  nspid: %i", nspid);
        }
        int plink = rtnl_link_get_link(link);
        if (plink) {
            printf("  link: %i", plink);
        }
        printf("\n");
    }

}

static int
mycb(struct nl_msg *msg, void *arg)
{
    //printf("cb\n");
    //nl_msg_dump(msg, stdout);
    // msg_parse seems to do nothing unless a cache exists
    nl_msg_parse(msg, myparse, NULL);
    return 0;
}

int main()
{
    const char *confdir_path = getenv("ENETMGR_CONFIGDIR");
    if (!confdir_path) {
        confdir_path = "/etc/enetmgr";
    };
    DIR *confdir = opendir(confdir_path);
    if (!confdir) {
        fprintf(stderr, "Could not open %s: %s\n", confdir_path, strerror(errno));
        return 1;
    }
    struct nl_sock *sock = nl_socket_alloc();
    nl_socket_disable_seq_check(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, mycb, NULL);
    nl_connect(sock, NETLINK_ROUTE);
    nl_socket_add_memberships(sock, RTNLGRP_LINK, 0);
    nl_socket_add_memberships(sock, RTNLGRP_IPV4_IFADDR, 0);
    nl_socket_add_memberships(sock, RTNLGRP_IPV6_IFADDR, 0);
    rtnl_route_alloc_cache(sock, 0, 0, &myroutecahe);
    rtnl_addr_alloc_cache(sock, &myaddrcache);
    rtnl_link_alloc_cache(sock, 0, &mylinkcache);
    printf("Socket port: %08x\n", nl_socket_get_local_port(sock));
    /* can get FD to pass to a select loop using
     *  nl_socket_get_fd(sock);
     * can set it to non-blocking mode to poll using
     *  nl_socket_set_nonblocking(sock);
     */
    struct dirent *dirent;
    while (dirent = readdir(confdir)) {
        if (dirent->d_name[0] == '.') {
            continue;
        }
        printf("%s\n", dirent->d_name);
    }
    /* Since we populated the link cache already, lets enumerate it */
    struct state state = {
        .target = "testbridge",
        .found = 0,
    };
    nl_cache_foreach(mylinkcache, linkinfo, &state);
    nl_cache_foreach(myaddrcache, addrinfo, NULL);
    if (state.found) {
        printf("Found %s, not configuring\n", state.target);
    } else {
        printf("Didn't find existing %s, configuring a new one\n", state.target);
        //struct rtnl_link *dev = rtnl_link_bridge_alloc();
        int res = rtnl_link_bridge_add(sock, state.target);
        if (res != NLE_SUCCESS) {
            printf(" Failed to create bridge: %s\n", nl_geterror(res));
        }
        /* If it was successful, we will get a new/update link event in
         * nl_recvmsgs_default loop. Once that happens, we can assign
         * addresses or whatever. */
    }
    while (0) {
        nl_recvmsgs_default(sock);
    }
    nl_socket_free(sock);
    return 0;
}
