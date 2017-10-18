#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <stdio.h>

struct nl_cache *myroutecahe = NULL;
struct nl_cache *mylinkcache = NULL;

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
    }
    if (islink) {
        /* Hold your breath, cross your fingers... */
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
linkinfo(struct nl_object *obj, void *arg)
{
    int type = nl_object_get_msgtype(obj);
    //printf("type: %x\n", type);
    if (type == RTM_NEWLINK) {
        struct rtnl_link *link = (struct rtnl_link *)obj;
        printf(" %i\n", rtnl_link_get_ifindex(link));
        printf("  name: %s\n", rtnl_link_get_name(link));
        int master = rtnl_link_get_master(link);
        if (master) {
            printf("  master: %i\n", master);
        }
        int32_t outns;
        int ret;
        ret = rtnl_link_get_link_netnsid(link, &outns);
        if (ret == 0) {
            printf("  nsid: %i\n", outns);
        }
        pid_t nspid = rtnl_link_get_ns_pid(link);
        if (nspid) {
            printf("  nspid: %i\n", nspid);
        }
        int plink = rtnl_link_get_link(link);
        if (plink) {
            printf("  link: %i\n", plink);
        }
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
    //printf("int: %li\n", sizeof(int));
    //printf("int*: %li\n", sizeof(int*));
    struct nl_sock *sock = nl_socket_alloc();
    //printf("good\n");
    nl_socket_disable_seq_check(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, mycb, NULL);
    nl_connect(sock, NETLINK_ROUTE);
    nl_socket_add_memberships(sock, RTNLGRP_LINK, 0);
    //mycahe = link_alloc_cache(sock);
    rtnl_route_alloc_cache(sock, 0, 0, &myroutecahe);
    rtnl_link_alloc_cache(sock, 0, &mylinkcache);
    printf("Socket port: %08x\n", nl_socket_get_local_port(sock));
    /* can get FD to pass to a select loop using
     *  nl_socket_get_fd(sock);
     * can set it to non-blocking mode to poll using
     *  nl_socket_set_nonblocking(sock);
     */
    /* Since we populated the link cache already, lets enumerate it */
    nl_cache_foreach(mylinkcache, linkinfo, NULL);
    while (1) {
        nl_recvmsgs_default(sock);
    }
    nl_socket_free(sock);
    return 0;
}
