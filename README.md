This dir contains bash/python scripts for HPC management!

# dstat_ib.py
InfiniBand/RoCE traffic monitoring plugin for dstat on Linux.
- Install: `sudo cp dstat_ib.py /usr/share/dstat/dstat_ib.py`
- Run: `dstat -a --ib`
- Monitor a specific port: `dstat --ib -N mlx5_0:1`
- Monitor multiple ports and total: `dstat --ib -N mlx5_3:1,mlx5_2:1,total`
- Replace device names and port numbers with those on your host.
- Output: `recv` and `send` rates in bytes/sec; defaults to the total of all discovered ports.


# loginGuard.sh
A continuous Linux/Bash 4+ HPC login-node guard monitoring all accounts; root UID/EUID is always report-only.
- CPU limit: at least 80% of one logical CPU for 20 consecutive minutes, per process.
- Memory limit: RSS at least the smaller of 48 GiB or 20% of host RAM for 10 minutes, per process.
- Every excessive CPU/RSS sample is logged, including exempt users/commands; compression/transfer commands bypass non-root CPU enforcement only.
- Create `userwhitelist` beside the script (one username per line, or empty); listed users are logged but never signaled.
- The whitelist reloads each cycle; unresolved users or an unreadable whitelist stop the guard for safety.
- Dry run (default): `sudo bash loginGuard.sh`; enable termination: `sudo env DRY_RUN=0 bash loginGuard.sh`.
- Termination sends TERM, then KILL after 10 seconds if needed; settings can be overridden via environment variables.
- Run one instance per node (not periodic cron); sample every 60 seconds; local logs/lock: `/var/log/loginGuard/`.
- Install and start as a systemd service: `sudo bash loginGuard.sh-systemd-install.sh` (self-contained; creates an empty `/etc/loginGuard/userwhitelist` on first install); to enable termination, set `DRY_RUN=0` in `/etc/loginGuard/loginGuard.conf`, then run `sudo systemctl restart loginGuard.service`.
