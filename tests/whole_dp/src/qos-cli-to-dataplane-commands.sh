#!/bin/vcli -f
#
# This bash/vcli script is run on a Vyatta Router with QoS configured on it.
# The output of the script contains the current QoS CLI configuration
# commands, and the QoS configuration commands that are sent down to the
# vyatta-dataplane when the configuration is committed.
#
# Get the current state on QoS debugging in the vyatta-dataplane.
#
# Collect the QoS CLI configuration commands.
#
# Determines the name of the last interface with QoS configured.
# Deletes the QoS configuration from that interfaces.
# Turn QoS debugging on.
# Re-attaches the QoS configuration to the interface
# Reset QoS debugging to its saved setting.
# Calls the qos-cli-to-dataplane-commands.py python script to generate
# the list of CLI configuration commands and vyatta-dataplane QoS
# configuration messages.
#

saved_qos_debug=`/opt/vyatta/bin/vplsh -l -c "debug" | grep qos | wc -l`
#echo "QoS debug: $saved_qos_debug"

configure

#
# Find out what interfaces QoS is configured on and count how many there are
#
temp_file=$(mktemp)
run show configuration commands | match qos | match interface > $temp_file
lines=`run show configuration commands | match qos | match interface | wc -l`
if [ $lines -ne 1 ]; then
    lines=`expr $lines - 1`
    #
    # Delete all but the last line in the file, leaving just one interface
    #
    #echo "lines: $lines"
    edit_cmd="1,"$lines"d"
else
    edit_cmd=""
fi

#echo "edit_cmd: $edit_cmd"
set_if_qos_cmd=`sed "$edit_cmd" $temp_file`

#
# Delete the QoS configuration from one interface
#
delete_if_qos_cmd=`sed -e "$edit_cmd" -e 's/set /delete /' $temp_file`
#echo "delete: $delete_if_qos_cmd"
$delete_if_qos_cmd
commit

#
# Turn on QoS debugging so that the vyatta-dataplane QoS messages appear in
# the system log.
#
if [ $saved_qos_debug -ne 1 ]; then
    /opt/vyatta/bin/vplsh -lc "debug qos"
fi

#
# Reattach the QoS configuration to the interface
#
#echo "set: $set_if_qos_cmd"
$set_if_qos_cmd
commit

#
# Reset QoS debugging to its original setting
#
if [ $saved_qos_debug -eq 0 ]; then
    /opt/vyatta/bin/vplsh -lc "debug -qos"
fi
end_configure

#
# Call the python script to format the required output
#
echo "Writing QoS configuration information into qos_ut_test_cmds.txt"

./qos-cli-to-dataplane-commands.py > qos_ut_test_cmds.txt

rm $temp_file
