#!/usr/bin/env bash

# set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_PATH="$0"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

DO_INSTALL=0
DO_UNINSTALL=0
DO_PATCH=0
MANAGER=""
MANAGER_PORT=""
REG_PORT=""

REPO_UPDATED=0

PKGTYPE=""
PKGMGR=""
ARCH=""
BASE_PATH="/usr/share/cakra"
LOG_PATH="/var/log/cakra-edr.log"

EDR_VER="4.14.1"
DPKG_EDR_URL=https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${EDR_VER}-1_amd64.deb
RPM_EDR_URL=https://packages.wazuh.com/4.x/yum/wazuh-agent-${EDR_VER}-1.x86_64.rpm
HIDS_VER="5.8.2"
DPKG_HIDS_URL=https://pkg.osquery.io/deb/osquery_${HIDS_VER}-1.linux_amd64.deb
RPM_HIDS_URL=https://pkg.osquery.io/rpm/osquery-${HIDS_VER}-1.linux.x86_64.rpm
NIDS_VER="8.7.1"
DPKG_NIDS_URL=https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-${NIDS_VER}-amd64.deb
RPM_NIDS_URL=https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-${NIDS_VER}-x86_64.rpm
DFIR_VER="0.75.5"
DFIR_MAJOR_VER="0.75"
DFIR_URL=https://github.com/Velocidex/velociraptor/releases/download/v${DFIR_MAJOR_VER}/velociraptor-v${DFIR_VER}-linux-amd64

## Prints information
logger() {
  no_print=0
  now=$(date +'%m/%d/%Y %H:%M:%S')
  case $1 in
    "-e")
      mtype="ERROR:"
      message="$2"
      ;;
    "-w")
      mtype="WARNING:"
      message="$2"
      ;;
    "-d")
      mtype="DEBUG:"
      message="$2"
      no_print=1
      ;;
    *)
      mtype="INFO:"
      message="$1"
      ;;
  esac
  echo $now $mtype $message >> "$LOG_PATH"
  if [ $no_print -eq 0 ]; then
    echo $now $mtype $message
  fi
}

if command -v dpkg >/dev/null 2>&1; then
  PKGTYPE=dpkg
elif command -v rpm >/dev/null 2>&1; then
  PKGTYPE=rpm
else
  logger -e "Unsupported system. No supported package system detected."
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  PKGMGR=apt-get
elif command -v yum >/dev/null 2>&1; then
  PKGMGR=yum
elif command -v zypper >/dev/null 2>&1; then
  PKGMGR=zypper
else
  logger -e "Unsupported system. No supported package manager detected."
  exit 1
fi

if command -v uname >/dev/null 2>&1; then
  ARCH=$(uname -m)
else
  logger -e "Cannot determine system architecture."
  exit 1
fi

if [ ${ARCH} != "x86_64" ]; then
    logger -e "Unsupported system. No supported architecture detected."
    exit 1;
fi

REQUIRED_COMMANDS="sleep awk grep"
MISSING_COMMANDS=""

for cmd in $REQUIRED_COMMANDS; do
  command -v "$cmd" >/dev/null 2>&1 || MISSING_COMMANDS="$MISSING_COMMANDS $cmd"
done

if [ -n "$MISSING_COMMANDS" ]; then
  logger -e "Unsupported system. Missing required commands:$MISSING_COMMANDS" >&2
  exit 1
fi

isPort() {
  case "$1" in
    ''|*[!0-9]*)
      return 1
      ;;
    *)
      [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
      ;;
  esac
}

usage() {
  cat <<'EOF'
Usage:
  wazuh-edr-installer.sh -i --manager <host> --manager-port <port> --registration-port <port> --key <customer-key> --customer <customer>
  wazuh-edr-installer.sh -p --key <customer-key>
  wazuh-edr-installer.sh -u

Options:
  -i      Install
  -p      Patch
  -u      Uninstall

Install Parameters:
  --manager <host>            Wazuh manager address (IP/FQDN)
  --manager-port <port>       Manager port
  --registration-port <port>  Registration port
  --key <customer-key>        Customer registration key
  --customer <customer>       Customer identifier

Patch Parameters:
  --key <customer-key>        Customer registration key
EOF
}

errorArgs() {
  echo "ERROR: $1"
  usage
  exit 1
}

parseArgs() {
  # Show help if no args
  if [ $# -eq 0 ]; then
    usage
    exit 1
  fi
  
  # Parse args
  while [ $# -gt 0 ]; do
    case "$1" in
      -i)
        DO_INSTALL=1
        shift
        ;;
      -p)
        DO_PATCH=1
        shift
        ;;
      -u)
        DO_UNINSTALL=1
        shift
        ;;
      --manager)
        MANAGER="${2:-}"; shift 2
        ;;
      --manager-port|--manager_port)
        MANAGER_PORT="${2:-}"; shift 2
        ;;
      --registration-port|--registration_port)
        REG_PORT="${2:-}"; shift 2
        ;;
      --key)
        KEY="${2:-}"; shift 2
        ;;
      --customer)
        CUSTOMER="${2:-}"; shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        errorArgs "unknown argument: $1"
        ;;
    esac
  done

  # Validate action
  if [ "$DO_INSTALL" -eq 1 ] && [ "$DO_PATCH" -eq 1 ] && [ "$DO_UNINSTALL" -eq 1 ]; then
    errorArgs "choose only one action: -i, -p or -u"
  fi
  if [ "$DO_INSTALL" -eq 0 ] && [ "$DO_PATCH" -eq 0 ] && [ "$DO_UNINSTALL" -eq 0 ]; then
    errorArgs "missing action: use -i, -p or -u"
  fi
  if [ "$DO_INSTALL" -eq 1 ]; then
    if [ -z "$MANAGER" ]; then
      errorArgs "missing --manager"
    fi
    if [ -z "$MANAGER_PORT" ]; then
      errorArgs "missing --manager-port"
    else
      if ! isPort "$MANAGER_PORT"; then
        errorArgs "invalid --manager-port: $MANAGER_PORT"
      fi
    fi
    if [ -z "$REG_PORT" ]; then
      errorArgs "missing --registration-port"
    else
      if ! isPort "$REG_PORT"; then
        errorArgs "invalid --registration-port: $REG_PORT"
      fi
    fi
    if [ -z "$KEY" ]; then
      errorArgs "missing --key"
    fi
    if [ -z "$CUSTOMER" ]; then
      errorArgs "missing --customer"
    fi
  fi
  if [ "$DO_PATCH" -eq 1 ]; then
    if [ -z "$KEY" ]; then
      errorArgs "missing --key"
    fi
  fi
}

isPkgInstalled() {
  pkg="$1"
  case "$PKGTYPE" in
    dpkg)
      dpkg -s "$pkg" >> "$LOG_PATH" 2>&1
      ;;
    rpm)
      rpm -q "$pkg" >> "$LOG_PATH" 2>&1
      ;;
    *)
      logger -e "Unsupported system. No supported package system detected."
      return 2
      ;;
  esac
}

downloadFile() {
  logger -d "Downloading file from $1 to $2"
  url="$1"
  dest="$2"

  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url" >> "$LOG_PATH" 2>&1 || return 1
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$dest" "$url" >> "$LOG_PATH" 2>&1 || return 1
    return 0
  fi

  return 1
}


updateRepo() {
  if [ "${REPO_UPDATED:-0}" -eq 0 ]; then
    case "$PKGMGR" in
      apt-get)
        apt-get update >> "$LOG_PATH" 2>&1
        ;;
      yum)
        yum makecache >> "$LOG_PATH" 2>&1
        ;;
      zypper)
        zypper refresh >> "$LOG_PATH" 2>&1
        ;;
      *)
        logger -e "Unsupported system. No supported package manager detected."
        exit 1
        ;;
    esac
    REPO_UPDATED=1
  fi
}

installCmdFromRepo() {
  cmd="$1"
  pkg="${2:-$1}"
  if command -v "$cmd" >/dev/null 2>&1; then
    logger -d "$cmd already installed.. skipping.."
  else
    updateRepo
    case "$PKGMGR" in
      apt-get)
        apt-get install -y "$pkg" >> "$LOG_PATH" 2>&1
        ;;
      yum)
        yum install -y "$pkg" >> "$LOG_PATH" 2>&1
        ;;
      zypper)
        zypper -n install "$pkg" >> "$LOG_PATH" 2>&1
        ;;
      *)
        logger -e "Unsupported system. No supported package manager detected."
        exit 1
        ;;
    esac
    if command -v "$cmd" >/dev/null 2>&1; then
      logger -d "$cmd installed successfully."
    else
      logger -e "Failed to install $cmd."
      exit 1
    fi
  fi
}

startService() {
  svc="$1"
  svc_name="${2:-$1}"
  if [ "$#" -lt 1 ]; then
    logger -e "startService must be called with at least 1 argument."
    exit 1
  fi

  logger "Starting ${svc_name}..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >> "$LOG_PATH" 2>&1 || return 1
    systemctl enable "${svc}.service" >> "$LOG_PATH" 2>&1 || return 1
    logger -d "${svc_name} enabled to start on boot."
    systemctl start  "${svc}.service" >> "$LOG_PATH" 2>&1 || {
      logger -e "${svc_name} could not be started."
      command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
      return 1
    }
    logger "${svc_name} started."
    return 0
  fi

  if command -v service >/dev/null 2>&1; then
    if command -v chkconfig >/dev/null 2>&1; then
      chkconfig "$svc" on >> "$LOG_PATH" 2>&1 || {
        logger -e "${svc_name} could not be started."
        command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
        return 1
      }
      logger -d "${svc_name} enabled to start on boot."
    fi
    service "$svc" start >> "$LOG_PATH" 2>&1 || {
      logger -e "${svc_name} could not be started."
      command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
      return 1
    }
    logger "${svc_name} started."
    if [ -x "/etc/init.d/$svc" ]; then
      "/etc/init.d/$svc" start >> "$LOG_PATH" 2>&1 || {
        logger -e "${svc_name} could not be started."
        command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
        return 1
      }
      logger "${svc_name} started."
    fi
    return 0
  fi

  if [ -x "/etc/init.d/$svc" ]; then
    if command -v chkconfig >/dev/null 2>&1; then
      chkconfig "$svc" on >> "$LOG_PATH" 2>&1 || {
        logger -e "${svc_name} could not be started."
        command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
        return 1
      }
      logger "$svc enabled to start on boot."
    fi
    "/etc/init.d/$svc" start >> "$LOG_PATH" 2>&1 || {
      logger -e "${svc_name} could not be started."
      command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
      return 1
    }
    logger "$svc service started."
    return 0
  fi

  if [ -x "/etc/rc.d/init.d/$svc" ]; then
    "/etc/rc.d/init.d/$svc" start >> "$LOG_PATH" 2>&1 || {
      logger -e "${svc_name} could not be started."
      command -v journalctl >/dev/null 2>&1 && journalctl -u "$svc" >> "$LOG_PATH" 2>&1
      return 1
    }
    logger "$svc service started."
    return 0
  fi

  logger -e "$svc could not start. No service manager found on the system."
  return 1
}

createInstallPath() {
  if [ ! -d "${BASE_PATH}" ]; then
    mkdir -p "${BASE_PATH}"
  fi
}

checkTcpPort() {
  host="$1"
  port="$2"
  timeout_sec="${3:-5}"
  logger "Attempting network connection to $host on port $port"

  if [ -n "$BASH_VERSION" ] && command -v timeout >/dev/null 2>&1; then
    logger -d "Checking TCP port with bash method is available"
  elif command -v nc >/dev/null 2>&1; then
    logger -d "Checking TCP port with nc method is available"
  elif command -v telnet >/dev/null 2>&1; then
    logger -d "Checking TCP port with telnet method is available"
  else
    logger -e "Unsupported system. No available method to check network connection."
    exit 1
  fi

  if [ -n "$BASH_VERSION" ] && command -v timeout >/dev/null 2>&1; then
    logger -d "Checking TCP port $port on host $host with timeout $timeout_sec seconds using bash"
    timeout -k 1 "$timeout_sec" bash -c "exec 3<>/dev/tcp/$host/$port" \
      >/dev/null 2>&1 && return 0
  fi

  if command -v nc >/dev/null 2>&1; then
    logger -d "Checking TCP port $port on host $host with timeout $timeout_sec seconds using nc"
    nc -z -w "$timeout_sec" "$host" "$port" >/dev/null 2>&1 && return 0
  fi

  if command -v telnet >/dev/null 2>&1; then
    logger -d "Checking TCP port $port on host $host using telnet"
    connectionReg=$(sleep 2 | telnet $host $port 2>/dev/null | grep Connected | awk '{print $1}')
    if [ "$connectionReg" == "Connected" ]; then
      return 0
    fi
  fi

  return 1
}

checkReqPort() {
  host="$1"
  port="$2"
  if checkTcpPort $host $port; then
    logger "Successfully connected to $host on port $port"
  else
    logger -e "Failed to connect to $host on port $port"
    exit 1
  fi
}

edrNetworkCheck() {
  checkReqPort "$MANAGER" "$MANAGER_PORT"
  checkReqPort "$MANAGER" "$REG_PORT"
}


configEDR() {
  new_install=${1:-0}
  logger "Updating Cakra EDR configuration..."
  mkdir -p "$BASE_PATH/scripts" >> "$LOG_PATH" 2>&1
  downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/local_internal_options.conf" "/var/ossec/etc/local_internal_options.conf" >> "$LOG_PATH" 2>&1
  chown -R root:wazuh /var/ossec/etc/local_internal_options.conf >> "$LOG_PATH" 2>&1
  downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/open-audit.sh" "$BASE_PATH/scripts/open-audit.sh" >> "$LOG_PATH" 2>&1
  chown root:wazuh "$BASE_PATH/scripts/open-audit.sh" >> "$LOG_PATH" 2>&1
  chmod +x "$BASE_PATH/scripts/open-audit.sh" >> "$LOG_PATH"
  if [ "$new_install" -eq 1 ]; then
    cat <<EOF > /var/ossec/etc/ossec.conf
<ossec_config>
  <client>
  <server>
    <address>$MANAGER</address>
    <port>$MANAGER_PORT</port>
    <protocol>tcp</protocol>
  </server>
  <notify_time>10</notify_time>
  <time-reconnect>60</time-reconnect>
  <auto_restart>yes</auto_restart>
  <crypto_method>aes</crypto_method>
</client>
</ossec_config>
EOF
    chown -R root:wazuh /var/ossec/etc/ossec.conf >> "$LOG_PATH" 2>&1
  fi
}

installEDR() {
  edrNetworkCheck
  logger "Checking Cakra EDR installation status..."
  if isPkgInstalled "wazuh-agent"; then
    logger "Cakra EDR already installed."
    configEDR
  else
    install_result=1
    logger "Installing Cakra EDR..."
    rm -rf /var/ossec >> "$LOG_PATH" 2>&1
    mkdir -p "$BASE_PATH/binaries" >> "$LOG_PATH" 2>&1
    if [ "${PKGTYPE}" == "dpkg" ]; then
      downloadFile "${DPKG_EDR_URL}" "${BASE_PATH}/binaries/wazuh-agent_${EDR_VER}-1_amd64.deb"
      dpkg -i "${BASE_PATH}/binaries/wazuh-agent_${EDR_VER}-1_amd64.deb" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    elif [ "${PKGTYPE}" == "rpm" ]; then
      downloadFile "${RPM_EDR_URL}" "${BASE_PATH}/binaries/wazuh-agent-${EDR_VER}-1.x86_64.rpm"
      rpm -i "${BASE_PATH}/binaries/wazuh-agent-${EDR_VER}-1.x86_64.rpm" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    else
      logger -e "Unsupported system. No supported package system detected."
      exit 1
    fi
    if [ "$install_result" -ne 0 ]; then
      logger -e "Cakra EDR installation failed."
      exit 1
    else
      logger "Cakra EDR installed successfully."
      /var/ossec/bin/agent-auth -m ${MANAGER} -p ${REG_PORT} -P "${KEY}" -G "Linux_${CUSTOMER}" >> "$LOG_PATH" 2>&1
      configEDR 1
      startService wazuh-agent "Cakra EDR"
    fi
  fi
}

configHIDS() {
  logger "Updating Cakra HIDS configuration..."
  downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/osquery.conf" "/etc/osquery/osquery.conf" >> "$LOG_PATH" 2>&1
  downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/osquery.flags" "/etc/osquery/osquery.flags" >> "$LOG_PATH" 2>&1
  if command -v ln >/dev/null 2>&1; then
    ln -s /etc/osquery/osquery.flags /etc/osquery/osquery.flags.default >> "$LOG_PATH" 2>&1
  fi
}

installHIDS() {
  logger "Checking Cakra HIDS installation status..."
  if isPkgInstalled "osquery"; then
    logger "Cakra HIDS already installed."
    configHIDS
  else
    install_result=1
    logger "Installing Cakra HIDS..."
    mkdir -p "$BASE_PATH/binaries" >> "$LOG_PATH" 2>&1
    if [ "${PKGTYPE}" == "dpkg" ]; then
      downloadFile "${DPKG_HIDS_URL}" "${BASE_PATH}/binaries/osquery_${HIDS_VER}-1.linux_amd64.deb"
      dpkg -i "${BASE_PATH}/binaries/osquery_${HIDS_VER}-1.linux_amd64.deb" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    elif [ "${PKGTYPE}" == "rpm" ]; then
      downloadFile "${RPM_HIDS_URL}" "${BASE_PATH}/binaries/osquery-${HIDS_VER}-1.linux.x86_64.rpm"
      rpm -i "${BASE_PATH}/binaries/osquery-${HIDS_VER}-1.linux.x86_64.rpm" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    else
      logger -e "Unsupported system. No supported package system detected."
      exit 1
    fi
    if [ "$install_result" -ne 0 ]; then
      logger -e "Cakra HIDS installation failed."
      exit 1
    else
      logger "Cakra HIDS installed successfully."
      configHIDS
      startService osqueryd "Cakra HIDS"
    fi
  fi
}

configNIDS() {
  logger "Updating Cakra NIDS configuration..."
  downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/packetbeat.yaml" "/etc/packetbeat/packetbeat.yml" >> "$LOG_PATH" 2>&1
}

installNIDS() {
  logger "Checking Cakra NIDS installation status..."
  if isPkgInstalled "packetbeat"; then
    logger "Cakra NIDS already installed."
    configNIDS
  else
    install_result=1
    logger "Installing Cakra NIDS..."
    mkdir -p "$BASE_PATH/binaries" >> "$LOG_PATH" 2>&1
    if [ "${PKGTYPE}" == "dpkg" ]; then
      downloadFile "${DPKG_NIDS_URL}" "${BASE_PATH}/binaries/packetbeat-${NIDS_VER}-amd64.deb"
      dpkg -i "${BASE_PATH}/binaries/packetbeat-${NIDS_VER}-amd64.deb" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    elif [ "${PKGTYPE}" == "rpm" ]; then
      downloadFile "${RPM_NIDS_URL}" "${BASE_PATH}/binaries/packetbeat-${NIDS_VER}-x86_64.rpm"
      rpm -i "${BASE_PATH}/binaries/packetbeat-${NIDS_VER}-x86_64.rpm" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    else
      logger -e "Unsupported system. No supported package system detected."
      exit 1
    fi
    if [ "$install_result" -ne 0 ]; then
      logger -e "Cakra NIDS installation failed."
      exit 1
    else
      logger "Cakra NIDS installed successfully."
      configNIDS
      startService packetbeat "Cakra NIDS"
    fi
  fi
}

configDFIR() {
  logger "Updating Cakra DFIR configuration..."
  downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/${KEY}.yaml" "/etc/velociraptor/client.config.yaml" >> "$LOG_PATH" 2>&1
  startService velociraptor-client "Cakra DFIR"
}

installDFIR() {
  logger "Checking Cakra DFIR installation status..."
  if isPkgInstalled "velociraptor-client"; then
    logger "Cakra DFIR already installed."
    configDFIR
  else
    install_result=1
    logger "Installing Cakra DFIR..."
    mkdir -p "$BASE_PATH/binaries" >> "$LOG_PATH" 2>&1
    mkdir -p "$BASE_PATH/config" >> "$LOG_PATH" 2>&1
    downloadFile "${DFIR_URL}" "${BASE_PATH}/binaries/velociraptor"
    chmod +x "${BASE_PATH}/binaries/velociraptor" >> "$LOG_PATH" 2>&1
    downloadFile "https://raw.githubusercontent.com/zharfanug/punggawa-assets/refs/heads/main/cakra/scripts/${KEY}.yaml" "${BASE_PATH}/config/${KEY}.yaml" >> "$LOG_PATH" 2>&1
    cd "$BASE_PATH/binaries"
    if [ "${PKGTYPE}" == "dpkg" ]; then
      "${BASE_PATH}/binaries/velociraptor" debian client --config "${BASE_PATH}/config/${KEY}.yaml" --output "${BASE_PATH}/binaries/" >> "$LOG_PATH" 2>&1
      dpkg -i "${BASE_PATH}/binaries/velociraptor_client_${DFIR_VER}_amd64.deb" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    elif [ "${PKGTYPE}" == "rpm" ]; then
      "${BASE_PATH}/binaries/velociraptor" rpm client --config "${BASE_PATH}/config/${KEY}.yaml" --output "${BASE_PATH}/binaries/" >> "$LOG_PATH" 2>&1
      rpm -Uvh "${BASE_PATH}/binaries/velociraptor_client_${DFIR_VER}_x86_64.rpm" >> "$LOG_PATH" 2>&1
      install_result="${PIPESTATUS[0]}"
    else
      logger -e "Unsupported system. No supported package system detected."
      exit 1
    fi
    if [ "$install_result" -ne 0 ]; then
      logger -e "Cakra DFIR installation failed."
      exit 1
    else
      logger "Cakra DFIR installed successfully."
      startService velociraptor-client "Cakra DFIR"
    fi
  fi
}

doInstall() {
  if [ ! -f "$LOG_PATH" ]; then
    touch "$LOG_PATH"
  fi
  createInstallPath
  installEDR
  installHIDS
  installNIDS
  installDFIR
  logger "Cakra EDR installation completed successfully."
}

uninstallItem() {
  pkg="$1"
  pkg_name="${2:-$1}"
  if isPkgInstalled "$pkg"; then
    logger "Uninstalling ${pkg_name}..."
    case "$PKGMGR" in
      apt-get)
        apt-get purge -y "$pkg" >> "$LOG_PATH" 2>&1
        ;;
      yum)
        yum remove -y "$pkg" >> "$LOG_PATH" 2>&1
        ;;
      zypper)
        zypper -n remove "$pkg" >> "$LOG_PATH" 2>&1
        ;;
      *)
        logger -e "Unsupported system. No supported package manager detected."
        exit 1
        ;;
    esac
    logger "${pkg_name} uninstalled successfully."
  else
    logger "${pkg_name} is not installed. Skipping.."
  fi
}

doUninstall() {
  if [ ! -f "$LOG_PATH" ]; then
    touch "$LOG_PATH"
  fi
  logger "Starting Cakra EDR uninstallation..."
  uninstallItem "wazuh-agent" "Cakra EDR"
  uninstallItem "osquery" "Cakra HIDS"
  uninstallItem "packetbeat" "Cakra NIDS"
  uninstallItem "velociraptor-client" "Cakra DFIR"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >> "$LOG_PATH" 2>&1 || true
  fi
  rm -rf "$BASE_PATH" >> "$LOG_PATH" 2>&1
  logger "Cakra EDR uninstallation completed successfully."
}

patchItem() {
  item="$1"
  pkg="$2"
  func=$3
  if isPkgInstalled "$pkg"; then
    logger -d "${item} is installed. Proceeding with patch..."
    if [ -n "$func" ]; then
      "$func"
    fi
    logger -d "${item} patch applied successfully."
  else
    logger -e "${item} is not installed. Please run the installation before applying this patch."
    exit 1
  fi
}

doPatches() {
  if [ ! -f "$LOG_PATH" ]; then
    touch "$LOG_PATH"
  fi
  logger "Starting Cakra EDR patching..."
  patchItem "Cakra EDR" "wazuh-agent" configEDR
  installHIDS
  installNIDS
  installDFIR
  logger "Cakra EDR patching completed successfully."
}

main() {
  parseArgs "$@"
  if [ "$DO_INSTALL" -eq 1 ]; then
    LOG_PATH="/var/log/cakra-edr-install.log"
    doInstall
  elif [ "$DO_PATCH" -eq 1 ]; then
    LOG_PATH="/var/log/cakra-edr-patch.log"
    doPatches
  elif [ "$DO_UNINSTALL" -eq 1 ]; then
    LOG_PATH="/var/log/cakra-edr-uninstall.log"
    doUninstall
  fi
}

main "$@"