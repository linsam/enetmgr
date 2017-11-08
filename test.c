#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/bridge.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

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
    void (*cb)(struct state *, int event, int ifindex, const char *name, const char *type, int master, int netnsid, pid_t nspid, int plink);
    char *helper;
};

static void addrinfo(struct nl_object *obj, void *arg);
static void linkinfo(struct nl_object *obj, void *arg);

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
        linkinfo(obj, arg);
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
    int msgtype = nl_object_get_msgtype(obj);
    struct state *state = arg;
    if (msgtype == RTM_NEWLINK || msgtype == RTM_DELLINK) {
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
        } else {
            outns = 0;
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
        if (state && state->cb) {
            /* EVENT: 1=new, 2=remove */
            state->cb(state, msgtype == RTM_NEWLINK ? 1 : 2, rtnl_link_get_ifindex(link), rtnl_link_get_name(link), type, master, outns, nspid, plink);
        }
    }

}

static int
mycb(struct nl_msg *msg, void *arg)
{
    //printf("cb\n");
    //nl_msg_dump(msg, stdout);
    // msg_parse seems to do nothing unless a cache exists
    nl_msg_parse(msg, myparse, arg);
    return 0;
}

void
fork_link_event(struct state *state, int event, int ifindex, const char *name, const char *type, int master, int netnsid, pid_t nspid, int plink)
{
    char ifindex_str[20];
    char master_str[20];
    char netnsid_str[20];
    char pid_str[20];
    char plink_str[20];
    char event_str[20];
    if (!state->helper) {
        return;
    }

    snprintf(ifindex_str, sizeof ifindex_str, "%i", ifindex);
    snprintf(master_str, sizeof master_str, "%i", master);
    snprintf(netnsid_str, sizeof netnsid_str, "%i", netnsid);
    snprintf(pid_str, sizeof pid_str, "%i", nspid);
    snprintf(plink_str, sizeof plink_str, "%i", plink);
    snprintf(event_str, sizeof event_str, "%i", event);
    pid_t child = fork();
    if (child) {
        int status;
        waitpid(child, &status, 0);
        return;
    }
    execl(state->helper, state->helper, "link", event_str, ifindex_str, name?name:"", type?type:"", master_str, netnsid_str, pid_str, plink_str, NULL);
    /* TODO: Show name of helper in error message */
    perror("Failed to run helper");
    exit(1);
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
    struct state state = {
        .target = "testbridge",
        .found = 0,
        .cb = fork_link_event,
    };
    struct nl_sock *sock = nl_socket_alloc();
    nl_socket_disable_seq_check(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, mycb, &state);
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
        if (strcmp(dirent->d_name, "helper") == 0) {
            char *buf = malloc(2048); /* TODO: Use whatever MAX_PATH is */
            if (buf) {
                state.helper = buf;
                snprintf(buf, 2048, "%s/%s", confdir_path, dirent->d_name);
                buf[2047] = '\0';
                FILE *f = fopen(buf, "r");
                if (!f) {
                    perror("read helper");
                } else {
                    int pos = fread(buf, 1, 2047, f);
                    fclose(f);
                    buf[pos] = '\0';
                    /* Remove last EOL. */
                    char * n = strrchr(buf, '\n');
                    if (n) *n = '\0';
                }
            }
        }
    }
    /* Since we populated the link cache already, lets enumerate it */
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
    while (1) {
        nl_recvmsgs_default(sock);
    }
    nl_socket_free(sock);
    return 0;
}
