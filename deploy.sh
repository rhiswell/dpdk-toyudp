#!/bin/bash

sender=192.168.122.166
reciver=192.168.122.217

RTE_SDK_PATH=/home/rh/dpdk-stable-17.05.2
RTE_TARGET=build
EXPECTED_DEVICE=0000:00:09.0
EXPECTED_IF=ens9

function build_project()
{
	local host=$1

	tar --exclude="../udpdemo/build" --exclude="../udpdemo/deploy.sh" \
		-cvf /tmp/udpdemo.tar ../udpdemo && \
		scp /tmp/udpdemo.tar rh@$host:. && \
		ssh $host "tar --no-same-owner -xvf udpdemo.tar && \
		cd udpdemo && RTE_SDK='$RTE_SDK_PATH' RTE_TARGET='$RTE_TARGET' make"
}

# Prepare memory and NIC for DPDK
function setup_rte()
{
	local host=$1

	# Prefer igb_uio
	ssh $host "cd '$RTE_SDK_PATH' && echo 'm' | sudo -S sh -c 'modprobe uio && \
		(rmmod igb_uio || true) && insmod ./build/kmod/igb_uio.ko && \
		(./usertools/dpdk-devbind.py --unbind $EXPECTED_DEVICE >/dev/null || true) && \
		./usertools/dpdk-devbind.py --bind=igb_uio $EXPECTED_DEVICE && \
		mkdir -p /mnt/huge && (umount /mnt/huge 2>/dev/null || true) && \
		mount -t hugetlbfs nodev /mnt/huge && \
		echo 64 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages' \
		2>/dev/null" && echo "$host is prepared"
}

function setup_nic()
{
	local host=$1;
	local ip_with_cidr=$2;

	ssh $host "echo 'm' | sudo -S sh -c '(echo -n $EXPECTED_DEVICE > \
		/sys/bus/pci/devices/$EXPECTED_DEVICE/driver/unbind || true) && \
		echo -n $EXPECTED_DEVICE > /sys/bus/pci/drivers/e1000/bind && \
		sleep 1 && ip addr add $ip_with_cidr dev $EXPECTED_IF && \
		ip link set $EXPECTED_IF up' 2>/dev/null" && \
		echo "$host is prepared"
}

function test()
{
	local pathname=$1
}

if [[ ! -z "$1" && "$1" = "setup" ]]; then
	for host in $sender $reciver
#	for host in $sender
	do
		setup_rte $host
	done
fi

if [[ ! -z "$1" && "$1" = "build" ]]; then
	for host in $sender $reciver
	do
		build_project $host
	done
fi

if [[ ! -z "$1" && "$1" = "normal" ]]; then
	setup_nic $reciver 192.168.1.2/24
fi
