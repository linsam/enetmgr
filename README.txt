eNetMgr - Embedded Network Manager

Purpose: be a lightweight manager for networks in embedded systems. The
general idea is that the FreeDesktop Network-Manager is a bit heavy (lots of
UI and dbus), but embedded systems could still benefit from something that
monitors the state of networking. Embedded systems already have daemon
monitors (runit, s6, nosh, other daemon-tools) and service management (nosh?,
s6-rc, anopa) that are lighter weight than systemd. It just misses a
monitor/manager for networking.
