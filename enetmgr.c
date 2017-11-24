#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/bridge.h>
#include <netlink/route/link/bonding.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <assert.h>

#if DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

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

struct interface {
    struct interface *next;
    char *name;
    int found;
    char *type;
};

struct state {
    struct interface *interfaces;
    struct interface *unconf;
    struct nl_sock *nlsocket;
    const char *confdir;
    void (*cb)(struct state *, int event, int ifindex, const char *name, const char *type, int master, int netnsid, pid_t nspid, int plink, char *carrier, char *operstate);
    char *helper;
};

int fileToBuf(const char *filename, char *buf, size_t max);

static void addrinfo(struct nl_object *obj, void *arg);
static void linkinfo(struct nl_object *obj, void *arg);

/** Allocate a new interface object, placing it in a list.
 *
 * Also returns a pointer to the new interface, in case caller wants to
 * modify it without having to search for it again.
 */
static struct interface *
addInterface(struct interface **head, const char *name)
{
    struct interface *interface = malloc(sizeof *interface);
    memset(interface, 0, sizeof *interface);
    interface->name = strdup(name);
    if (*head == NULL) {
        *head = interface;
    } else {
        struct interface *i = *head;
        while (i->next) {
            i = i->next;
        }
        i->next = interface;
    }
    return interface;
}

static struct interface *
findInterfaceByName(struct interface *head, const char *query)
{
    while (head) {
        if (strcmp(head->name, query) == 0) {
            return head;
        }
        head = head->next;
    }
    return head;
}

/** Read a one-liner config file and store it into buf.
 *
 * This will read text from the specified configuration file. The last EOL
 * will be stripped, if present. A string terminator will be added.
 *
 * As a consequence of the current implementation, a file consisting only
 * of an incomplete line will be read full. A file with multiple complete
 * lines and an incomplete line will result in the loss of the incomplete
 * line. This is possibly the worst "compromise" in the debate of partial
 * line handling.
 *
 * @param devname name of device which has the desired config file. May be
 * NULL to indicate global config.
 * @param name name of config file under device (or global if \p devname is
 * NULL).
 * @param [out] buf buffer to place the output.
 * @param max maximum number of bytes to read into buffer, including the
 * string terminator.
 *
 * @return number of bytes actually read, or -1 for error.
 * @note errno will be set if -1 is returned. The values can be any error
 * from the printf() family of functions, or from fopen, or as below:
 * @li ENOMEM not enough memory to perform operation. Typically, the buffer
 * for the filename wasn't large enough.
 */
int
confFileToBuf(struct state *state, const char *devname, const char *name, char *buf, size_t max)
{
    char fullname[1000];
    int res;
    if (devname) {
        res = snprintf(fullname, sizeof fullname, "%s/%s/%s", state->confdir, devname, name);
    } else {
        res = snprintf(fullname, sizeof fullname, "%s/%s", state->confdir, name);
    }
    if (res < 0 || res >= sizeof fullname) {
        /* error or truncation */
        if (res > 0) errno = ENOMEM; /* or maybe ENAMETOOLONG? or ERANGE? */
        return -1;
    }
    res = fileToBuf(fullname, buf, max);
    if (res == -1) {
        int tmp = errno;
        fprintf(stderr, "couldn't read %s: %s\n", fullname, strerror(errno));
        errno = tmp;
    }
    return res;
}

/** Like confFileToBuf, but don't display errors.
 */
int
confFileToBufSilent(struct state *state, const char *devname, const char *name, char *buf, size_t max)
{
    char fullname[1000];
    int res;
    if (devname) {
        res = snprintf(fullname, sizeof fullname, "%s/%s/%s", state->confdir, devname, name);
    } else {
        res = snprintf(fullname, sizeof fullname, "%s/%s", state->confdir, name);
    }
    if (res < 0 || res >= sizeof fullname) {
        /* error or truncation */
        if (res > 0) errno = ENOMEM; /* or maybe ENAMETOOLONG? or ERANGE? */
        return -1;
    }
    return fileToBuf(fullname, buf, max);
}

int
fileToBuf(const char *filename, char *buf, size_t max)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        return -1;
    }
    int pos = fread(buf, 1, max - 1, f);
    dprintf(stderr, "max = %li, pos = %i\n", max, pos);
    fclose(f);
    buf[pos] = '\0';
    /* Remove last EOL. */
    char * n = strrchr(buf, '\n');
    if (n) *n = '\0';
    /* TODO: for full partial line handling, only check the last char for
     * \n. Alternatively, for complete non-handling of partial line, set
     * index 0 to \0 if n is NULL.
     */
    dprintf("File read (%s). contents are: %s\n", filename, buf);
    if (n) return n-buf; /* TODO: check math.*/
    return pos; /* TODO: check math */
}

#define VI_OK 0
#define VI_ERROR -1
#define VI_BAD_TYPE 1

static int
validateInterface(struct state *state, struct interface *interface)
{
    char buf[1000];
    int ret = confFileToBuf(state, interface->name, "type", buf, sizeof buf);
    if (ret < 1) {
        return VI_ERROR;
    }
    if (strcmp(buf, "unmanaged") == 0) {
        ; /* ignore */
    } else if (strcmp(buf, "regular") == 0) {
        ; /* Ingore for now */
    } else if (strcmp(buf, interface->type) != 0) {
        return VI_BAD_TYPE;
    }
    return VI_OK;
}

static void
destroyInterface(struct state *state, const char *name)
{
    assert(0); /* TODO: Implementation */
    return;
}

/** Instantiate an interface by reading configuration.
 */
static void
createInterface(struct state *state, const char *name)
{
    char buf[1000];
    int ret = confFileToBuf(state, name, "type", buf, sizeof buf);
    if (ret < 1) {
        return;
    }
    printf("Setting up interface %s of type %s\n", name, buf);
    if (strcmp(buf, "unmanaged") == 0) {
        printf(" Device is unmanaged; not creating\n");
    } else if (strcmp(buf, "regular") == 0) {
        printf(" Physical device doesn't exist and can't create physical objects.\n");
    } else if (strcmp(buf, "bridge") == 0) {
        int res = rtnl_link_bridge_add(state->nlsocket, name);
        if (res != NLE_SUCCESS) {
            printf(" Failed to create bridge: %s\n", nl_geterror(res));
        }
    } else if (strcmp(buf, "bond") == 0) {
        int res = rtnl_link_bond_add(state->nlsocket, name, NULL);
        if (res != NLE_SUCCESS) {
            printf(" Failed to create bond: %s\n", nl_geterror(res));
        }
    } else if (strcmp(buf, "dummy") == 0) {
        printf(" dummy not yet implemented\n");
        //libnl3 doesn't seem to support creating a dummy device?
        //TODO: handroll creation request
    } else {
        fprintf(stderr, " Unknown type %s\n", buf);
    }
}

static void
configureInterface(struct state *state, struct interface *interface)
{
    char buf[1000];
    /* Check if this device wants a master */
    int ret = confFileToBufSilent(state, interface->name, "master", buf, sizeof buf);
    /* TODO: What about errors? If it is ENOENT we don't care. If it was
     * EPERM, maybe we care? What about ENOMEM or other errors where we
     * /should/ have read the file, but something went wrong?
     */
    if (ret > 0) {
        /* NOTE: according to libnl, older kernels require a legacy
         * interface. If we get -NLE_OPNOTSUPP, we may want to utilize that
         * method. Though, this is supposedly a working interface since
         * 2011; given that this is six years later; we'll probably only
         * add backwards compatibility if someone really needs it.
         */
        struct rtnl_link *master, *slave;
        master = rtnl_link_get_by_name(mylinkcache, buf);
        slave = rtnl_link_get_by_name(mylinkcache, interface->name);
        /* Note: An interface doesn't seem to need to be released from a
         * previous master prior to assigning a new one.
         */
        if (master && slave) {
            fprintf(stderr, "Set device %s to be slave of %s\n", interface->name, buf);
            /* TODO: error checking */
            rtnl_link_enslave(state->nlsocket, master, slave);
        } else {
            /* TODO: better reporting */
            fprintf(stderr, "something went wrong. master: %p, slave: %p\n", master, slave);
        }
    } else {
        /* Device shouldn't have a master */
        /* TODO: Check if device has master. If it does, release it. */
    }
    /* TODO: put other configuration we support here */
    return;
}

/** Update a cache entry.
 *
 * This function is based largely on pickup_checkdup_cb from libnl, but
 * with the added feature that we can add, update, or remove an entry.
 *
 * @param cache the cache to update.
 * @param obj the object to put into the cache.
 * @param remove if true, removes the object from the cache, if found.
 */
static void
updateCache(struct nl_cache *cache, struct nl_object *obj, int remove)
{
    struct nl_object *cache_obj = nl_cache_search(cache, obj);
    if (cache_obj) {
        if (remove) {
            nl_cache_remove(cache_obj);
            nl_object_put(cache_obj);
            return;
        }
        if (nl_object_update(cache_obj, obj) == 0) {
            nl_object_put(cache_obj);
            return;
        }
        /* Object isn't updatable, or other error. Remove it and add the
         * new one instead. */
        nl_cache_remove(cache_obj);
        nl_object_put(cache_obj);
    }
    if (remove) {
        /* Didn't find object in cache, but want to remove, so do nothing.
         */
        return;
    }
    nl_cache_add(cache, obj);
}

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
    if (nl_object_get_msgtype(obj) == RTM_NEWLINK) {
        dprintf(" New (or updated) link!\n");
        linkinfo(obj, arg);
        updateCache(mylinkcache, obj, 0);
    } else if (nl_object_get_msgtype(obj) == RTM_DELLINK) {
        dprintf(" Removed link!\n");
        linkinfo(obj, arg);
        updateCache(mylinkcache, obj, 1);
    } else if (nl_object_get_msgtype(obj) == RTM_NEWADDR) {
        dprintf(" New (or updated) address!\n");
        addrinfo(obj, NULL);
    } else if (nl_object_get_msgtype(obj) == RTM_DELADDR) {
        dprintf(" Removed address!\n");
        addrinfo(obj, NULL);
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
        struct interface *interface = findInterfaceByName(state->interfaces, rtnl_link_get_name(link));
        if (interface) {
            interface->found = 1;
        } else {
            /* TODO: print message? do something, like wild card check or
             * something?
             */
            interface = addInterface(&state->unconf, rtnl_link_get_name(link));
        }
        const char *type = rtnl_link_get_type(link);
        if (type) {
            printf("  type: %-11s", type);
            interface->type = strdup(type);
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
        char carrier[20];
        char operstate[20];
        rtnl_link_carrier2str(rtnl_link_get_carrier(link), carrier, sizeof carrier);
        rtnl_link_operstate2str(rtnl_link_get_operstate(link), operstate, sizeof operstate);
        printf("  carrier: %02hhx(%s)", rtnl_link_get_carrier(link), carrier);
        printf("  operate: %02hhx(%s)", rtnl_link_get_operstate(link), operstate);
        printf("\n");
        if (state && state->cb) {
            /* EVENT: 1=new, 2=remove */
            state->cb(state, msgtype == RTM_NEWLINK ? 1 : 2, rtnl_link_get_ifindex(link), rtnl_link_get_name(link), type, master, outns, nspid, plink, carrier, operstate);
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
fork_link_event(struct state *state, int event, int ifindex, const char *name, const char *type, int master, int netnsid, pid_t nspid, int plink, char *carrier, char *operstate)
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
    execl(state->helper, state->helper, "link", event_str, ifindex_str, name?name:"", type?type:"", master_str, netnsid_str, pid_str, plink_str, carrier, operstate, NULL);
    fprintf(stderr,"Failed to run helper %s: %s\n", state->helper, strerror(errno));
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
    struct nl_sock *sock = nl_socket_alloc();
    struct state state = {
        .cb = fork_link_event,
        .interfaces = NULL,
        .confdir = confdir_path,
        .nlsocket = sock,
    };
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
    nl_socket_set_nonblocking(sock);
    struct dirent *dirent;
    char *buf = malloc(2048); /* TODO: Use whatever MAX_PATH is */
    if (!buf) {
        perror("memory");
        return 1;
    }
    struct stat stats;
    while (dirent = readdir(confdir)) {
        if (dirent->d_name[0] == '.') {
            continue;
        }
        printf("%s\n", dirent->d_name);
        snprintf(buf, 2048, "%s/%s", confdir_path, dirent->d_name);
        int res = stat(buf, &stats);
        if (res != 0) {
            perror("stat");
            continue;
        }
        if (S_ISREG(stats.st_mode) && strcmp(dirent->d_name, "helper") == 0) {
            int size = confFileToBuf(&state, NULL, "helper", buf, 2048);
            if (size > 0) {
                state.helper = strdup(buf);
            }
        } else if (S_ISDIR(stats.st_mode)) {
            addInterface(&state.interfaces, dirent->d_name);
        } else {
            /* TODO: Maybe only when debug is set? */
            printf("WARNING: Ignoring %s\n", buf);
        }
    }
    free(buf);
    /* Since we populated the link cache already, lets enumerate it */
    nl_cache_foreach(mylinkcache, linkinfo, &state);
    nl_cache_foreach(myaddrcache, addrinfo, NULL);

    {
        struct interface *i;
        /* TODO: Calling these managed is confusing, given that they might
         * have a confuration type of unmanaged! This should mean "known by
         * configuration" or something. */
        printf("Initial pass complete.\n Existing managed interfaces:\n");
        for (i = state.interfaces; i; i = i->next) {
            if (i->found) {
                printf("  %s\n", i->name);
            }
        }
        printf("\n Existing unmanaged interfaces:\n");
        for (i = state.unconf; i; i = i->next) {
            printf("  %s\n", i->name);
        }
        printf("\n Non existant interfaces we are supposed to manage:\n");
        for (i = state.interfaces; i; i = i->next) {
            if (!i->found) {
                printf("  %s\n", i->name);
            }
        }
        /* Check existing devices for correct type. If they are
         * wrong, we'll have to remove them, set them as not found, and
         * allow the next section to add them as the correct type.
         */
        for (i = state.interfaces; i; i = i->next) {
            if (i->found) {
                int res = validateInterface(&state, i);
                if (res == VI_BAD_TYPE) {
                    fprintf(stderr, "WARNING: interface %s has wrong type. Removing. Will re-create with correct type.\n", i->name);
                    /* TODO: Verify device destruction, probably by
                     * pumping some events from the netlink socket */
                    destroyInterface(&state, i->name);
                    i->found = false;
                } else if (res != VI_OK) {
                    fprintf(stderr, "Unexpected validation result\n");
                }
            }
        }
        /* Now, let us instantiate all of the interfaces we are supposed to
         * manage. We won't fully configure them yet; they might depend on
         * other interfaces we haven't made quite yet.
         */
        for (i = state.interfaces; i; i = i->next) {
            if (!i->found) {
                createInterface(&state, i->name);
            }
        }

        /* Finally, let us configure the interfaces. Since everything
         * should exist at this point, setting up masters and such should
         * be fine at this stage.
         */
        for (i = state.interfaces; i; i = i->next) {
            configureInterface(&state, i);
        }
    }
    int sockfd = nl_socket_get_fd(sock);
    while (1) {
        fd_set rfd;
        int retval;
        FD_ZERO(&rfd);
        FD_SET(sockfd, &rfd);
        retval = select(sockfd + 1, &rfd, NULL, NULL, NULL);
        if (retval == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            return 1;
        }
        nl_recvmsgs_default(sock);
    }
    nl_socket_free(sock);
    return 0;
}
