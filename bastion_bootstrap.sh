#!/bin/bash -e
# Bastion Bootstrapping
# The script is based on AWS basition quick start. More detail can been found at https://github.com/aws-quickstart/quickstart-linux-bastion.


# Configuration
PROGRAM='Linux Bastion'

##################################### Functions Definitions
# 本脚本只支持Linux操作系统。
function checkos () {
    platform='unknown'
    unamestr=`uname`
    if [[ "${unamestr}" == 'Linux' ]]; then
        platform='linux'
    else
        echo "[WARNING] This script is not supported on MacOS or FreeBSD"
        exit 1
    fi
    echo "${FUNCNAME[0]} Ended"
}

# 初始化必要的目录和文件，并设置环境变量
# 其中在堡垒机上执行的所有命令将被记录在/var/log/bastion/bastion.log文件下。
function setup_environment_variables() {

    # LOGGING CONFIGURATION
    BASTION_MNT="/var/log/bastion"
    BASTION_LOG="bastion.log"
    echo "Setting up bastion session log in ${BASTION_MNT}/${BASTION_LOG}"
    mkdir -p ${BASTION_MNT}
    BASTION_LOGFILE="${BASTION_MNT}/${BASTION_LOG}"
    BASTION_LOGFILE_SHADOW="${BASTION_MNT}/.${BASTION_LOG}"
    touch ${BASTION_LOGFILE}
    if ! [ -L "$BASTION_LOGFILE_SHADOW" ]; then
      ln ${BASTION_LOGFILE} ${BASTION_LOGFILE_SHADOW}
    fi
    mkdir -p /usr/bin/bastion
    touch /tmp/messages
    chmod 770 /tmp/messages

    export BASTION_MNT BASTION_LOG BASTION_LOGFILE BASTION_LOGFILE_SHADOW 
}

function verify_dependencies(){
    echo "${FUNCNAME[0]} Ended"
}

function usage() {
    echo "$0 <usage>"
    echo " "
    echo "options:"
    echo -e "--help \t Show options for this script"
    echo -e "--banner \t Enable or Disable Bastion Message"
    echo -e "--enable \t SSH Banner"
    echo -e "--tcp-forwarding \t Enable or Disable TCP Forwarding"
    echo -e "--x11-forwarding \t Enable or Disable X11 Forwarding"
}

function chkstatus () {
    if [[ $? -eq 0 ]]
    then
        echo "Script [PASS]"
    else
        echo "Script [FAILED]" >&2
        exit 1
    fi
}

function osrelease () {
    OS=`cat /etc/os-release | grep '^NAME=' |  tr -d \" | sed 's/\n//g' | sed 's/NAME=//g'`
    if [[ "${OS}" == "Ubuntu" ]]; then
        echo "Ubuntu"
    elif [[ "${OS}" == "CentOS Linux" ]]; then
        echo "CentOS"
    else
        echo "Operating System Not Found"
    fi
}

# 修改sshd_config文件，当用户在堡垒机上执行shell命令时，将首先自动执行定义的脚本文件/usr/bin/basition/shell

function harden_ssh_security () {
    # Make OpenSSH execute a custom script on logins
    echo -e "\nForceCommand /usr/bin/bastion/shell" >> /etc/ssh/sshd_config

cat <<'EOF' >> /usr/bin/bastion/shell
bastion_mnt="/var/log/bastion"
bastion_log="bastion.log"
# Check that the SSH client did not supply a command. Only SSH to instance should be allowed.
export Allow_SSH="ssh"
export Allow_SCP="scp"
if [[ -z $SSH_ORIGINAL_COMMAND ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SSH ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SCP ]]; then
#Allow ssh to instance and log connection
    if [[ -z "$SSH_ORIGINAL_COMMAND" ]]; then
        /bin/bash
        exit 0
    else
        $SSH_ORIGINAL_COMMAND
    fi
    log_shadow_file_location="${bastion_mnt}/.${bastion_log}"
    log_file=`echo "$log_shadow_file_location"`
    DATE_TIME_WHOAMI="`whoami`:`date "+%Y-%m-%d %H:%M:%S"`"
    LOG_ORIGINAL_COMMAND=`echo "$DATE_TIME_WHOAMI:$SSH_ORIGINAL_COMMAND"`
    echo "$LOG_ORIGINAL_COMMAND" >> "${bastion_mnt}/${bastion_log}"
    log_dir="/var/log/bastion/"
else
# The "script" program could be circumvented with some commands
# (e.g. bash, nc). Therefore, I intentionally prevent users
# from supplying commands.

    echo "This bastion supports interactive sessions only. Do not supply a command"
    exit 1
fi
EOF

    # Make the custom script executable
    chmod a+x /usr/bin/bastion/shell

    release=$(osrelease)
    if [[ "${release}" == "CentOS" ]]; then
        semanage fcontext -a -t ssh_exec_t /usr/bin/bastion/shell
    fi

    echo "${FUNCNAME[0]} Ended"
}

function setup_logs () {
    echo "${FUNCNAME[0]} Started"
}

# 修改bashrc文件。当用户登录到堡垒机时，将自动执行bashrc文件。
function setup_os () {

    echo "${FUNCNAME[0]} Started"

    if [[ "${release}" == "CentOS" ]]; then
        bash_file="/etc/bashrc"
    else
        bash_file="/etc/bash.bashrc"
    fi

cat <<EOF >> "${bash_file}"
#Added by Linux bastion bootstrap
declare -rx IP=\$(echo \$SSH_CLIENT | awk '{print \$1}')
declare -rx BASTION_LOG=${BASTION_LOGFILE}
declare -rx PROMPT_COMMAND='history -a >(logger -t "[ON]:\$(date)   [FROM]:\${IP}   [USER]:\${USER}   [PWD]:\${PWD}" -s 2>>\${BASTION_LOG})'
EOF

    echo "Defaults env_keep += \"SSH_CLIENT\"" >> /etc/sudoers

    if [[ "${release}" == "Ubuntu" ]]; then
        user_group="ubuntu"
    elif [[ "${release}" == "CentOS" ]]; then
        user_group="root"
    fi

    chown root:"${user_group}" "${BASTION_MNT}"
    chown root:"${user_group}" "${BASTION_LOGFILE}"
    chown root:"${user_group}" "${BASTION_LOGFILE_SHADOW}"
    chmod 662 "${BASTION_LOGFILE}"
    chmod 662 "${BASTION_LOGFILE_SHADOW}"
    chattr +a "${BASTION_LOGFILE}"
    chattr +a "${BASTION_LOGFILE_SHADOW}"
    touch /tmp/messages
    chown root:"${user_group}" /tmp/messages

    if [[ "${release}" == "CentOS" ]]; then
        restorecon -v /etc/ssh/sshd_config
        systemctl restart sshd
    fi

    if [[ "${release}" == "SLES" ]]; then
        echo "0 0 * * * zypper patch --non-interactive" > ~/mycron
    elif [[ "${release}" == "Ubuntu" ]]; then
        apt-get install -y unattended-upgrades
        echo "0 0 * * * unattended-upgrades -d" > ~/mycron
    else
        echo "0 0 * * * yum -y update --security" > ~/mycron
    fi

    crontab ~/mycron
    rm ~/mycron

    echo "${FUNCNAME[0]} Ended"
}
# 不允许登录到堡垒机上的用户能通过ps -ef看到别的用户的进程信息。
function prevent_process_snooping() {
    # Prevent bastion host users from viewing processes owned by other users.
    mount -o remount,rw,hidepid=2 /proc
    awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
    echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
    echo "${FUNCNAME[0]} Ended"
}

##################################### End Function Definitions

# Call checkos to ensure platform is Linux
checkos
# Verify dependencies are installed.
verify_dependencies
# Assuming it is, setup environment variables.
setup_environment_variables

## set an initial value
SSH_BANNER="Kingsoft Cloud BASTION"

# Read the options from cli input
TEMP=`getopt -o h --longoptions help,banner:,enable:,tcp-forwarding:,x11-forwarding: -n $0 -- "$@"`
eval set -- "${TEMP}"


if [[ $# == 1 ]] ; then echo "No input provided! type ($0 --help) to see usage help" >&2 ; exit 1 ; fi

# extract options and their arguments into variables.
while true; do
    case "$1" in
        -h | --help)
            usage
            exit 1
            ;;
        --banner)
            BANNER_PATH="$2";
            shift 2
            ;;
        --enable)
            ENABLE="$2";
            shift 2
            ;;
        --tcp-forwarding)
            TCP_FORWARDING="$2";
            shift 2
            ;;
        --x11-forwarding)
            X11_FORWARDING="$2";
            shift 2
            ;;
        --)
            break
            ;;
        *)
            break
            ;;
    esac
done

# BANNER CONFIGURATION
BANNER_FILE="/etc/ssh_banner"
if [[ ${ENABLE} == "true" ]];then
    if [[ -z ${BANNER_PATH} ]];then
        echo "BANNER_PATH is null skipping ..."
    else
        echo "BANNER_PATH = ${BANNER_PATH}"
        echo "Creating Banner in ${BANNER_FILE}"
        echo "curl  -s ${BANNER_PATH} > ${BANNER_FILE}"
        curl  -s ${BANNER_PATH} > ${BANNER_FILE}
        if [[ -e ${BANNER_FILE} ]] ;then
            echo "[INFO] Installing banner ... "
            echo -e "\n Banner ${BANNER_FILE}" >>/etc/ssh/sshd_config
        else
            echo "[INFO] banner file is not accessible skipping ..."
            exit 1;
        fi
    fi
else
    echo "Banner message is not enabled!"
fi

#Enable/Disable TCP forwarding
TCP_FORWARDING=`echo "${TCP_FORWARDING}" | sed 's/\\n//g'`

#Enable/Disable X11 forwarding
X11_FORWARDING=`echo "${X11_FORWARDING}" | sed 's/\\n//g'`

echo "Value of TCP_FORWARDING - ${TCP_FORWARDING}"
echo "Value of X11_FORWARDING - ${X11_FORWARDING}"
if [[ ${TCP_FORWARDING} == "false" ]];then
    awk '!/AllowTcpForwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
    echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
    harden_ssh_security
fi

if [[ ${X11_FORWARDING} == "false" ]];then
    awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi

release=$(osrelease)
if [[ "${release}" == "Operating System Not Found" ]]; then
    echo "[ERROR] Unsupported Linux Bastion OS"
    exit 1
else
    setup_os
    setup_logs
fi

prevent_process_snooping

echo "Bootstrap complete."
