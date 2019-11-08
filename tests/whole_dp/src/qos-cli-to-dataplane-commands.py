#!/usr/bin/env python
#
# This python script is run on a Vyatta Router with QoS configured on it.
# The output of the script contains the current QoS CLI configuration
# commands, and the QoS configuration commands that are sent down to the
# vyatta-dataplane when the configuration is committed.
#
import os
import platform
import subprocess
import pwd
import tempfile


def RunGetOutput(cmd,chk_err=True):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT, trapping expected
    exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """
    try:
        output=subprocess.check_output(cmd,stderr=subprocess.STDOUT,
                                       shell=True)
    except subprocess.CalledProcessError,e :
        if chk_err :
            print('CalledProcessError.  Error Code is ' +
                  str(e.returncode)  )
            print('CalledProcessError.  Command string was ' + e.cmd  )
            print('CalledProcessError.  Command result was ' +
                  (e.output[:-1]).decode('latin-1'))
        return e.returncode, e.output.decode('latin-1')
    return 0, output.decode('latin-1')

def Run(cmd,chk_err=True):
    """
    Calls RunGetOutput on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    retcode,out=RunGetOutput(cmd,chk_err)
    return retcode

def get_qos_debug():
    """
    """
    rc, output = RunGetOutput('/opt/vyatta/bin/vplsh -lc "debug"')
    if "qos" in output:
        return True
    else:
        return False

def qos_debug(enable):
    """
    """
    if enable:
        qos_cmd = "qos"
    else:
        qos_cmd = "-qos"

    cmd = '/opt/vyatta/bin/vplsh -lc "debug {}"'.format(qos_cmd)
    rc, output = RunGetOutput(cmd)

def get_qos_cli_commands():
    """
    """
    cmd = "/bin/vcli -c 'run show configuration commands | match qos'"
    rc, output = RunGetOutput(cmd)
    return output

def get_journalctl_output():
    """
    """
    rc, output = RunGetOutput("journalctl -r -u vyatta-dataplane")
    return output


def main():
    """
    Test.
    """
    saved_qos_debug = get_qos_debug()
    cli_commands = get_qos_cli_commands()
    print "/*"
    print " * test_cmds created from:"
    print " *"
    for cli_command in cli_commands.splitlines():
        print " *   {}".format(cli_command)

    print " */"
    print ""

    qos_debug(True)

    qos_debug(saved_qos_debug)

    journal_output = get_journalctl_output()
    found_enable = False
    found_port = False
    cmd_list = []
    for logline in journal_output.splitlines():
        offset = logline.find("DATAPLANE: qos ")
        if offset != -1:
            qos_cmd = logline[offset+11:]
            if not found_enable and "enable" in logline:
                found_enable = True

            if found_enable:
                cmd_line = qos_cmd.replace("qos ", "", 1)
                index = cmd_line.find(" ") + 1
                cmd_line = cmd_line[index:]
                cmd_list.append(cmd_line)

            if found_enable and "port subports" in logline:
                break

    cmd_list.reverse()
    print "const char *test_cmds[] = {"
    for cmd_line in cmd_list:
        if "enable" in cmd_line:
            print '\t"{}"'.format(cmd_line)
        else:
            print '\t"{}",'.format(cmd_line)

    print "};"

if __name__ == '__main__' :
    main()
