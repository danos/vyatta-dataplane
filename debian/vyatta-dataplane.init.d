#! /bin/bash

### BEGIN INIT INFO
# Provides:          vyatta-dataplane
# Required-Start:    $syslog $remote_fs $local_fs
# Required-Stop:     $syslog $remote_fs $local_fs
# X-Start-Before:    vyatta-router vyatta-routing vplane-controller
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: networking dataplane
# Description: Vyatta Dataplane system setup
### END INIT INFO

progname=${0##*/}
ACTION=$1

# dataplane paths
PRODUCT="vPlane"
CONFIG=/etc/vyatta/dataplane.conf
DATAPLANE=/usr/sbin/dataplane
DATAPLANE_PID=/var/run/dataplane.pid
DATAPLANE_SOCKET=/var/run/vplane.socket

test -f /etc/default/dataplane  &&  .  /etc/default/dataplane

# Allow a platform to override the defaults by setting up
# the variables in /etc/default/dataplane
DATAPLANE_ARGS=${DATAPLANE_ARGS:="-u dataplane -g adm"}
DPDK_ARGS=${DPDK_ARGS:="--syslog local6 --log-level 7"}
HUGEPAGES=${HUGEPAGES:=0}

export PATH

. /lib/lsb/init-functions

test -r /etc/default/vyatta && . /etc/default/vyatta

# Check for dataplane application
[ -x "$DATAPLANE" ] || exit 0

# Check if dataplane not configured
if [ ! -r $CONFIG ]; then
    log_failure_msg "$PRODUCT missing config file '$CONFIG'"
    exit 0
fi

# Check boot cmdline args
for bootarg in $(< /proc/cmdline); do
    case "$bootarg" in
        no-dataplane) NO_DATAPLANE=true ;;
    esac
done

# Make runtime directory
run_dir=/var/run/dataplane
if [ ! -d $run_dir ]; then
    mkdir -p $run_dir
    chown dataplane:dataplane $run_dir
    chmod 755 $run_dir
fi

# Wait for dataplane to make /var/run/vplane.socket
# This is to work around ordering issues with dataplane
# and controller during boot
wait_for_dataplane() {
    local i=0

    while [ $i -lt 20 ]; do
	[ -S "$DATAPLANE_SOCKET" ] && break
	sleep 2
	echo -n .
	i=$(($i+1))
    done
}

start() {
    log_daemon_msg "Starting $PRODUCT services"

    # if no-dataplane on boot cmdline then don't start
    if [ "$NO_DATAPLANE" ]; then
	log_action_end_msg 0 "$PRODUCT disabled"
	exit 0
    fi

    # append on cpu and memory channel args
    DPDK_ARGS+=" $(/lib/vplane/vplane-eal-args $CONFIG)"

    log_progress_msg "log"
    /lib/vplane/vplane-dist-log || exit 1

    log_progress_msg "huge"
    /lib/vplane/vplane-hugepages set $HUGEPAGES || exit 1

    log_progress_msg "xen"
    /lib/vplane/vplane-xen || exit 1

    log_progress_msg "modules"
    /lib/vplane/vplane-modules load || exit 1

    log_progress_msg "unbind"
    /lib/vplane/vplane-uio || exit 1

    log_progress_msg "dataplane"
    ulimit -n 10000	# allow lots of file descriptors

    rm -f $DATAPLANE_SOCKET
    start-stop-daemon --start --oknodo --quiet --name dataplane \
      --pidfile $DATAPLANE_PID --make-pidfile --startas $DATAPLANE \
      --background --nicelevel -10 -- $DATAPLANE_ARGS -- $DPDK_ARGS

    wait_for_dataplane

    log_end_msg $?
}

stop() {
    if [ "$NO_DATAPLANE" ]; then
	exit 0
    fi

    log_daemon_msg "Stopping $PRODUCT services"
    log_progress_msg "dataplane"
    start-stop-daemon --stop --quiet --retry 5 --name dataplane \
	--pidfile=$DATAPLANE_PID --remove-pidfile
    rm -f $DATAPLANE_SOCKET

    log_progress_msg "huge"
    /lib/vplane/vplane-hugepages clean

    log_progress_msg "modules"
    /lib/vplane/vplane-modules unload

    log_success_msg
}

case "$ACTION" in
    start) start ;;
    stop) stop ;;
    restart|force-reload) stop; start ;;
    *)	log_failure_msg "action unknown: $ACTION" ;
	false ;;
esac

exit $?
