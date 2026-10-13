#!/usr/bin/env bash
# Standalone installer: the complete guard is embedded below; no downloads are used.
set -euo pipefail
export LC_ALL=C
umask 077

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
(( BASH_VERSINFO[0] >= 4 )) || die 'Bash 4 or newer is required.'
(( EUID == 0 )) || die 'Run this installer as root.'
[[ $(uname -s) == Linux ]] || die 'This installer requires Linux.'
for command in systemctl install awk getconf getent readlink flock date mkdir sleep dirname cat chown chmod; do
    command -v "$command" >/dev/null || die "Missing command: $command"
done
[[ -d /run/systemd/system ]] || die 'A running systemd system instance is required.'
[[ -x /bin/bash ]] || die '/bin/bash is required.'
/bin/bash -c '(( BASH_VERSINFO[0] >= 4 ))' || die '/bin/bash must be Bash 4 or newer.'

SCRIPT=/usr/local/sbin/loginGuard.sh
CONFIG_DIR=/etc/loginGuard
WHITELIST=$CONFIG_DIR/userwhitelist
CONFIG=$CONFIG_DIR/loginGuard.conf
UNIT=/etc/systemd/system/loginGuard.service
LOG_DIR=/var/log/loginGuard

# Refuse symlinks and unexpected file types at managed destinations.
for directory in /usr/local/sbin "$CONFIG_DIR" /etc/systemd/system "$LOG_DIR"; do
    [[ ! -L $directory ]] || die "Refusing symlink directory: $directory"
    [[ ! -e $directory || -d $directory ]] || die "Not a directory: $directory"
done
for file in "$SCRIPT" "$WHITELIST" "$CONFIG" "$UNIT"; do
    [[ ! -L $file ]] || die "Refusing symlink file: $file"
    [[ ! -e $file || -f $file ]] || die "Not a regular file: $file"
done

# Stop an existing service before replacing its executable or unit.
if systemctl cat loginGuard.service >/dev/null 2>&1; then
    systemctl stop loginGuard.service
fi
install -d -o root -g root -m 0755 /usr/local/sbin "$CONFIG_DIR" /etc/systemd/system
install -d -o root -g root -m 0700 "$LOG_DIR"

# Preserve administrator-managed whitelist and configuration on reinstall.
if [[ ! -e $WHITELIST ]]; then
    install -o root -g root -m 0600 /dev/null "$WHITELIST"
fi
if [[ ! -e $CONFIG ]]; then
    install -o root -g root -m 0600 /dev/null "$CONFIG"
    cat > "$CONFIG" <<'LOGINGUARD_CONFIG'
# systemd EnvironmentFile: edit values here, then restart loginGuard.service.
# Observation only by default; set DRY_RUN=0 to enable process termination.
WORK_DIR=/var/log/loginGuard
USERWHITELIST=/etc/loginGuard/userwhitelist
SAMPLE_SECONDS=60
CPU_PERCENT=80
CPU_SECONDS=1200
MEMORY_ENABLED=1
MEMORY_GIB=48
MEMORY_PERCENT=20
MEMORY_SECONDS=600
DRY_RUN=1
TERM_GRACE_SECONDS=10
LOGINGUARD_CONFIG
fi
chown root:root "$WHITELIST" "$CONFIG"
chmod 0600 "$WHITELIST" "$CONFIG"

install -o root -g root -m 0755 /dev/null "$SCRIPT"
cat > "$SCRIPT" <<'LOGINGUARD_SCRIPT'
#!/usr/bin/env bash
# HPC login-node process guard for Linux / Bash 4+; runs continuously.
# Observe first: sudo bash loginGuard.sh
# Enable termination: sudo env DRY_RUN=0 bash loginGuard.sh
# userwhitelist: one username per line; blank lines and # comments are allowed.
# Whitelisted users are monitored and logged but never signaled.
# Limits are per process; use user-level cgroups for aggregate resource limits.
set -uo pipefail
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK_DIR=${WORK_DIR:-/var/log/loginGuard}
USERWHITELIST=${USERWHITELIST:-$SCRIPT_DIR/userwhitelist}
SAMPLE_SECONDS=${SAMPLE_SECONDS:-60}
CPU_PERCENT=${CPU_PERCENT:-80}       # 100% represents one logical CPU, not the whole host.
CPU_SECONDS=${CPU_SECONDS:-1200}     # Consecutive excessive CPU usage, not process age.
MEMORY_ENABLED=${MEMORY_ENABLED:-1}
MEMORY_GIB=${MEMORY_GIB:-48}
MEMORY_PERCENT=${MEMORY_PERCENT:-20} # Use the smaller of the fixed and percentage limits.
MEMORY_SECONDS=${MEMORY_SECONDS:-600}
DRY_RUN=${DRY_RUN:-1}
TERM_GRACE_SECONDS=${TERM_GRACE_SECONDS:-10}
# Match actual executable basenames from /proc/PID/exe, not command-line keywords.
# These commands bypass CPU limits only; memory limits still apply.
# Do not add general-purpose interpreters such as bash, python, or java.
CPU_ALLOWLIST=${CPU_ALLOWLIST:-"gzip gunzip pigz unpigz bzip2 bunzip2 pbzip2 lbzip2 xz unxz pixz zstd unzstd lz4 zip unzip tar rsync scp sftp ssh sshd curl wget cp mv dd rclone bbcp"}

die() { printf '%s\n' "$*" >&2; exit 1; }
for setting in SAMPLE_SECONDS CPU_PERCENT CPU_SECONDS MEMORY_GIB MEMORY_PERCENT MEMORY_SECONDS TERM_GRACE_SECONDS; do
    value=${!setting}
    [[ $value =~ ^[1-9][0-9]*$ ]] || die "$setting must be a positive integer"
done
(( MEMORY_PERCENT <= 100 )) || die 'MEMORY_PERCENT must not exceed 100'
[[ $DRY_RUN =~ ^[01]$ && $MEMORY_ENABLED =~ ^[01]$ ]] || die 'DRY_RUN and MEMORY_ENABLED must be 0 or 1'
(( EUID == 0 )) || die 'Run as root to read and signal other users processes'
for command in awk getconf getent readlink flock date mkdir sleep; do
    command -v "$command" >/dev/null || die "Missing command: $command"
done
[[ -r $USERWHITELIST ]] || die "Cannot read whitelist: $USERWHITELIST (an empty file is allowed)"
umask 077
mkdir -p -- "$WORK_DIR" || die "Cannot create log directory: $WORK_DIR"
# WORK_DIR must be managed by root and must not be writable by ordinary users.
exec 9>"$WORK_DIR/guard.lock"
flock -n 9 || die 'Another guard instance is already running'
LOG_FILE=$WORK_DIR/guard.log
CLK_TCK=$(getconf CLK_TCK)
PAGE_KIB=$(( $(getconf PAGESIZE) / 1024 ))
TOTAL_KIB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
MEMORY_LIMIT_KIB=$(( MEMORY_GIB * 1024 * 1024 ))
PERCENT_LIMIT_KIB=$(( TOTAL_KIB * MEMORY_PERCENT / 100 ))
(( PERCENT_LIMIT_KIB < MEMORY_LIMIT_KIB )) && MEMORY_LIMIT_KIB=$PERCENT_LIMIT_KIB
log() { printf '%s %s\n' "$(date '+%F %T%z')" "$*" >> "$LOG_FILE"; }

declare -A whitelist_uids allowed_cpu prev_ticks prev_time cpu_over mem_over seen
load_whitelist() {
    local line username extra entry name password uid rest
    [[ -r $USERWHITELIST ]] || die "Cannot read whitelist: $USERWHITELIST"
    whitelist_uids=()
    # Accept CRLF files and a final line without a newline.
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        read -r username extra <<< "$line"
        [[ -z $username || $username == \#* ]] && continue
        # Resolve each account explicitly; this also works with LDAP enumeration disabled.
        entry=$(getent passwd "$username") || die "Cannot resolve whitelisted user: $username"
        IFS=: read -r name password uid rest <<< "$entry"
        [[ $uid =~ ^[0-9]+$ ]] || die "Invalid UID for whitelisted user: $username"
        whitelist_uids["$uid"]=1
    done < "$USERWHITELIST"
}
for executable in $CPU_ALLOWLIST; do allowed_cpu["$executable"]=1; done

# comm may contain spaces and parentheses; fields begin after the last ') '.
read_process() {
    local pid=$1 line tail
    local -a fields
    # Processes can exit between enumeration and reading; suppress expected open errors.
    IFS= read -r line 2>/dev/null < "/proc/$pid/stat" || return 1
    tail=${line##*) }
    read -r -a fields <<< "$tail"
    (( ${#fields[@]} >= 22 )) || return 1
    [[ ${fields[0]} != Z ]] || return 1
    p_start=${fields[19]}
    p_ticks=$(( fields[11] + fields[12] ))
    p_rss=$(( fields[21] * PAGE_KIB ))
    read -r p_uid p_euid < <(awk '/^Uid:/ {print $2, $3; exit}' "/proc/$pid/status" 2>/dev/null) || return 1
    [[ $p_uid =~ ^[0-9]+$ && $p_euid =~ ^[0-9]+$ ]] || return 1
    p_exe=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || return 1
}

# Recheck process identity before signaling to reduce PID-reuse risks.
same_process() {
    local pid=$1 start=$2 uid=$3 exe=$4
    read_process "$pid" || return 1
    [[ $p_start == "$start" && $p_uid == "$uid" && $p_exe == "$exe" ]]
}
terminate_process() {
    local pid=$1 start=$2 uid=$3 exe=$4 reason=$5
    same_process "$pid" "$start" "$uid" "$exe" || return
    # Root-owned or root-privileged processes are always report-only.
    if (( p_uid == 0 || p_euid == 0 )); then
        log "ROOT_REVIEW pid=$pid uid=$p_uid euid=$p_euid exe=$exe $reason"
        return
    fi
    # Refresh exemptions before each signal, including after the TERM grace period.
    load_whitelist
    if [[ -n ${whitelist_uids[$uid]+x} ]]; then
        log "WHITELIST_EXEMPT pid=$pid uid=$uid exe=$exe $reason"
        return
    fi
    if (( DRY_RUN )); then
        log "WOULD_TERMINATE pid=$pid uid=$uid exe=$exe $reason"
        return
    fi
    same_process "$pid" "$start" "$uid" "$exe" || return
    (( p_uid != 0 && p_euid != 0 )) || return
    if kill -TERM -- "$pid" 2>/dev/null; then
        log "TERM pid=$pid uid=$uid exe=$exe $reason"
        sleep "$TERM_GRACE_SECONDS"
        if same_process "$pid" "$start" "$uid" "$exe"; then
            load_whitelist
            if [[ -n ${whitelist_uids[$uid]+x} ]]; then
                log "WHITELIST_EXEMPT_KILL pid=$pid uid=$uid exe=$exe"
                return
            fi
            same_process "$pid" "$start" "$uid" "$exe" || return
            (( p_uid != 0 && p_euid != 0 )) || return
            if kill -KILL -- "$pid" 2>/dev/null; then
                log "KILL pid=$pid uid=$uid exe=$exe $reason"
            else
                log "KILL_FAILED pid=$pid uid=$uid"
            fi
        fi
    else
        log "TERM_FAILED pid=$pid uid=$uid"
    fi
}

trap 'log "STOP"; exit 0' INT TERM
log "START dry_run=$DRY_RUN cpu=${CPU_PERCENT}%/${CPU_SECONDS}s memory_enabled=$MEMORY_ENABLED memory=${MEMORY_LIMIT_KIB}KiB/${MEMORY_SECONDS}s whitelist=$USERWHITELIST"
while :; do
    load_whitelist
    seen=()
    for proc_dir in /proc/[0-9]*; do
        pid=${proc_dir##*/}
        read_process "$pid" || continue
        # Monitor all accounts; exclude only this guard's own process.
        (( pid != $$ )) || continue
        uid=$p_uid euid=$p_euid start=$p_start exe=$p_exe ticks=$p_ticks rss=$p_rss
        executable=${exe##*/}
        key=$pid:$start:$uid:$exe
        seen["$key"]=1
        read -r uptime _ < /proc/uptime
        now=${uptime%%.*}
        # Log excessive samples independently of exemptions and enforcement timers.
        # CPU requires two samples; RSS can be logged on the first observation.
        cpu=unknown
        cpu_high=0
        if [[ -n ${prev_time[$key]+x} ]]; then
            elapsed=$(( now - prev_time[$key] ))
            if (( elapsed > 0 && elapsed <= SAMPLE_SECONDS * 2 )); then
                delta=$(( ticks - prev_ticks[$key] ))
                cpu=$(( delta * 100 / CLK_TCK / elapsed ))
                (( cpu >= CPU_PERCENT )) && cpu_high=1
            fi
        fi
        if (( cpu_high || rss >= MEMORY_LIMIT_KIB )); then
            rss_percent=$(awk -v rss="$rss" -v total="$TOTAL_KIB" 'BEGIN {printf "%.2f", rss * 100 / total}')
            cpu_exempt=0
            user_exempt=0
            root_report_only=0
            [[ -n ${allowed_cpu[$executable]+x} ]] && cpu_exempt=1
            [[ -n ${whitelist_uids[$uid]+x} ]] && user_exempt=1
            event=LOAD
            if (( uid == 0 || euid == 0 )); then
                event=ROOT_LOAD
                root_report_only=1
                cpu_exempt=0
            fi
            log "$event pid=$pid start_ticks=$start uid=$uid euid=$euid exe=$exe cpu=${cpu}% rss=${rss}KiB rss_percent=${rss_percent}% cpu_exempt=$cpu_exempt user_exempt=$user_exempt root_report_only=$root_report_only"
        fi
        if [[ -n ${prev_time[$key]+x} ]]; then
            elapsed=$(( now - prev_time[$key] ))
            # Reset after long sampling gaps rather than assuming continuous excessive usage.
            if (( elapsed > 0 && elapsed <= SAMPLE_SECONDS * 2 )); then
                delta=$(( ticks - prev_ticks[$key] ))
                cpu=$(( delta * 100 / CLK_TCK / elapsed ))
                if { [[ -z ${allowed_cpu[$executable]+x} ]] || (( uid == 0 || euid == 0 )); } && (( cpu >= CPU_PERCENT )); then
                    cpu_over["$key"]=$(( ${cpu_over[$key]:-0} + elapsed ))
                else
                    cpu_over["$key"]=0
                fi
                # Count an interval only when both RSS samples exceed the memory limit.
                if (( MEMORY_ENABLED && rss >= MEMORY_LIMIT_KIB )); then
                    if [[ -n ${mem_over[$key]+x} ]]; then
                        mem_over["$key"]=$(( ${mem_over[$key]} + elapsed ))
                    else
                        mem_over["$key"]=0
                    fi
                else
                    unset 'mem_over[$key]'
                fi
                reason=""
                (( ${cpu_over[$key]:-0} >= CPU_SECONDS )) && reason="cpu=${cpu}% cpu_over=${cpu_over[$key]}s"
                if (( ${mem_over[$key]:-0} >= MEMORY_SECONDS )); then
                    reason="$reason rss=${rss}KiB memory_over=${mem_over[$key]}s"
                fi
                if [[ -n $reason ]]; then
                    terminate_process "$pid" "$start" "$uid" "$exe" "$reason"
                    cpu_over["$key"]=0
                    unset 'mem_over[$key]'
                fi
            else
                cpu_over["$key"]=0
                unset 'mem_over[$key]'
            fi
        elif (( MEMORY_ENABLED && rss >= MEMORY_LIMIT_KIB )); then
            mem_over["$key"]=0
        fi
        prev_ticks["$key"]=$ticks
        prev_time["$key"]=$now
    done
    # Discard state for exited or replaced processes.
    for key in "${!prev_time[@]}"; do
        if [[ -z ${seen[$key]+x} ]]; then
            unset 'prev_ticks[$key]' 'prev_time[$key]' 'cpu_over[$key]' 'mem_over[$key]'
        fi
    done
    sleep "$SAMPLE_SECONDS"
done
LOGINGUARD_SCRIPT
/bin/bash -n "$SCRIPT"

install -o root -g root -m 0644 /dev/null "$UNIT"
cat > "$UNIT" <<'LOGINGUARD_UNIT'
[Unit]
Description=Login node process resource guard
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/loginGuard/loginGuard.conf
ExecStart=/bin/bash /usr/local/sbin/loginGuard.sh
Restart=on-failure
RestartSec=30
KillMode=control-group
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
LOGINGUARD_UNIT

systemctl daemon-reload
systemctl enable loginGuard.service
systemctl restart loginGuard.service
if ! systemctl is-active --quiet loginGuard.service; then
    systemctl --no-pager --full status loginGuard.service || true
    die 'loginGuard.service is not active; inspect its journal and configuration.'
fi
systemctl --no-pager --full status loginGuard.service
printf '\nInstallation complete; loginGuard.service is enabled and active.\n'
printf 'Configuration: %s\nWhitelist: %s\nLogs: %s/guard.log\n' "$CONFIG" "$WHITELIST" "$LOG_DIR"
printf 'Service journal: journalctl -u loginGuard.service\n'
printf 'New installations default to DRY_RUN=1: log only, no process termination.\n'
printf 'To enable termination, set DRY_RUN=0 in %s, then restart loginGuard.service.\n' "$CONFIG"
printf 'Existing configuration and whitelist were preserved; check DRY_RUN before use.\n'
printf 'After editing configuration: systemctl restart loginGuard.service\n'
