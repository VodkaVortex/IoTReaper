#!/bin/sh

ACTION=$1
FILE=$2
TABLE=$3
PRIO=$4


if [ $# -ne 4 ];then
	echo "Parameter error"
	echo "Usage: $0 add|del file table"
	exit 1 
fi

rts=`cat $FILE`
if [ -z -rts ] ;then
	echo "cannot find file. "
	exit 1
fi

add_route_rule()
{
	if [ $FILE = /var/CTC.list ]; then
	 	for ip in $rts;do
			ip rule add to $ip table  $1 prio $PRIO
	 	done
 	elif [ $FILE = /var/CNC.list ]; then
	 	for ip in $rts;do
			ip rule add to $ip table  $1 prio $PRIO
	 	done
	elif [ $FILE = /var/CMC.list ]; then
	 	for ip in $rts;do
			ip rule add to $ip table  $1 prio $PRIO
	 	done
 	elif [ $FILE = /var/EDU.list ]; then
	 	for ip in $rts;do
			ip rule add to $ip table  $1 prio $PRIO
	 	done
	 fi
}


del_route_rule()
{
	if [ $FILE = /var/CTC.list ]; then
	 	for ip in $rts;do
			ip rule del to $ip table  $1 prio $PRIO
	 	done
 	elif [ $FILE = /var/CNC.list ]; then
	 	for ip in $rts;do
			ip rule del to $ip table  $1 prio $PRIO
	 	done
	elif [ $FILE = /var/CMC.list ]; then
	 	for ip in $rts;do
			ip rule del to $ip table  $1 prio $PRIO
	 	done
 	elif [ $FILE = /var/EDU.list ]; then
	 	for ip in $rts;do
			ip rule del to $ip table  $1 prio $PRIO
	 	done
	 fi
}

case $ACTION in
    add)
    add_route_rule $TABLE ;;
    del)
    del_route_rule $TABLE ;;
    *)
    echo "Usage: $0 add |del file table "
    exit 1 ;;
esac

