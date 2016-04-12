#!/bin/sh
# (c) 2015, The MITRE Corporation. All rights reserved.
# Source code distributed pursuant to license agreement.
#
# Usage: . ../funcs.sh
# This script provides some functionality used by bootstrap scripts.

#=====================Message Colors=========================
FAIL=$(tput setaf 1) #red
PASS=$(tput setaf 2) #green
HEAD=$(tput setaf 5) #magenta
INFO=$(tput setaf 6) #cyan
END=$(tput sgr0)   #ends color
#============================================================

verify()
{
    PIP='pip'
    if [ -z "$OS" ]
    then
        #printf "${INFO}Testing Computer's Architecture${END}\n"
        ARCH=$(uname -m | sed 's/x86_//;s/amd//;s/i[3-6]86/32/')
        if [ "$ARCH" -ne '64' ];
        then
            printf "${FAIL}Non 64-bit system detected${END}\n"
            exit
        #else
        #    printf "${PASS}Architecure 64-bit Passed${END}\n"
        fi
        #printf "${INFO}Testing the distro type${END}\n"
        OS=''
        VER=''
        REL=''
        # Using lsb-release because os-release not available on Ubuntu 10.04
        if [ -f /etc/redhat-release ];
        then
            OS=$(cat /etc/redhat-release | sed 's/ [Enterprise|release|Linux release].*//')
            VER=$(cat /etc/redhat-release | sed 's/.*release //;s/ .*$//')
            #Redhat/CentOS release version
            REL=$(echo $VER | sed 's/.[0-9].[0-9]*//;s/.[0-9]$//')
            if [ $REL -lt 7 ];
            then
                #change for RHEL/CentOS < Release 7
                PIP='pip2.7'
            fi
        elif command -v lsb_release >/dev/null 2>&1
        then
            OS=$(lsb_release -i| sed 's/Distributor ID:\t//')
            VER=$(lsb_release -r| sed 's/Release:\t//')
        else
            OS=$(uname -s)
            VER=$(uname -r)
        fi
        OS="$(echo "$OS" | tr "[:upper:]" "[:lower:]")"
        VER="$(echo "$VER" | tr "[:upper:]" "[:lower:]")"
        # Let's export these, so we don't have to repeat this in every bootstrap
        export OS
        export PIP
        export VER
        export REL
    fi
}

depend_crits()
{
    if [ -f requirements.txt ];
    then
        printf "${HEAD}Installing Python Dependencies${END}\n"
        sudo -E ${PIP} install -U -r requirements.txt
        if [ $? -ne 0 ]
        then
            printf "${FAIL}Dependency installation failed!${END}\n"
            exit
        else
            printf "${PASS}Dependency installation complete!${END}\n"
        fi
    fi
}

# Creates Default Database Files
create_files()
{
    #TODO fix the fixed paths
    #Perhaps we'll do this later
    if [ ! -e /data/crits_services ];
    then
        printf "${HEAD}Creating Services Folder${END}\n"
        sudo mkdir -v -p /data/crits_services
    fi
    #It used to be /data/crits_services
    sudo chown -R $USER:$GROUP /data/crits_services
    chmod -R -v 0755 /data/crits_services
}

# Error Message
exit_restart()
{
    printf "\n${HEAD}Error: To restart at this step: sh $0 $1${END}\n"
    exit
}




