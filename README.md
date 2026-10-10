This dir contains bash/python scripts for HPC management!

# dstat_ib.py
InfiniBand/RoCE traffic monitoring plugin for dstat on Linux.
- Install: `sudo cp dstat_ib.py /usr/share/dstat/dstat_ib.py`
- Run: `dstat -a --ib`
- Monitor a specific port: `dstat --ib -N mlx5_0:1`
- Monitor multiple ports and total: `dstat --ib -N mlx5_3:1,mlx5_2:1,total`
- Replace device names and port numbers with those on your host.
- Output: `recv` and `send` rates in bytes/sec; defaults to the total of all discovered ports.


