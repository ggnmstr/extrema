# extrema - EXTension REsource MAnagement in PostgreSQL 

This extension allows user to limit other extensions usage of resources (currently, only CPU, RAM, VmSwap and cpuset) by adding them to corresponding cgroups. 
These limitations can be easily configured using PostgreSQL's GUC mechanism.

Currently it only supports extensions that are in *shared_preload_libraries*, the extension is also designed to be in *shared_preload_libraries*, also it works **ONLY** with cgroup v2. 

It relies on a hook that is executed by Postmaster when it registers bgworker. 
Currently extension ships with a patch that adds required hook.

## OOM Killer warning

Extrema allows user to limit extensions' bgworkers both RAM and VmSwap usage. 

However, whenever any process of PostgreSQL gets killed (including extensions' bgworkers), **ALL** other PostgreSQL processes (excluding *postmaster*) are restarted, which may lead to perfomance struggling and other problems.

## Installation

1. Apply a patch to stable PostgreSQL 17:

``` shell
user@pc /postgres/contrib/extrema> git checkout REL_17_STABLE
user@pc /postgres/contrib/extrema> git apply extrema_hook_patch.diff
```

If patch conflitcs with branch, you can reset to specific commit that will work:
**709ce29b16569de7ed7d013399a6249849eaae40**
``` shell
user@pc /postgres/contrib/extrema> git checkout REL_17_STABLE
user@pc /postgres/contrib/extrema> git reset --hard 709ce29b16569de7ed7d013399a6249849eaae40
user@pc /postgres/contrib/extrema> git apply extrema_hook_patch.diff
```

Don't forget to configure, make and install PostgreSQL after you apply the patch to source code.


2. Install extension: 
``` shell 
user@pc /postgres/contrib/extrema> make
user@pc /postgres/contrib/extrema> make install
```

It is not necessary to **CREATE EXTENSION**, just setting it up in *shared_preload_libraries* should be enough, but if you want to be able to get a fancy view on your limitations (see below), do this: 
``` sql
CREATE EXTENSION extrema;
```

## Running with systemd

There are two main ways to run postgres with extrema on a systemd based machine:
1. **User** slice 
2. Custom **not-user** slice 

Main difference between them is that at this moment you can't have *cpuset* controller enabled in a user-slice cgroup.

### User slice

This is just as you would usually run Postgres, just make sure required extensions (including extrema) are present in *shared_preload_libraries*.
``` shell
user@pc /Work/test> postgres -D db_test/
```

You can use systemd-run to run postgres in a created/existing cgroup and adjust some settings:

``` shell
user@pc /Work/test> systemd-run --user --scope  -p "Delegate=yes" \
                                            -p "CPUAccounting=true" \
                                            -p "MemoryAccounting=true" \
                                            --slice=postgres.slice \
                                            postgres -D db_test/
```

### Custom slice

First of all, create desired slice in /sys/fs/cgroup:

``` shell
user@pc /Work/test> sudo -i
root@pc /> cd /sys/fs/cgroup/
root@pc /> echo "+cpu" > cgroup.subtree_control
root@pc /> echo "+memory" > cgroup.subtree_control
root@pc /> echo "+cpuset" > cgroup.subtree_control
root@pc /> mkdir myslice.slice
root@pc /> chown -R user myslice.slice/
```

Then run using systemd-run:

``` shell
user@pc /Work/test> systemd-run  --scope  -p "Delegate=yes" \
                                          -p "CPUAccounting=true" \
                                          -p "MemoryAccounting=true" \
                                          -p "AllowedCPUs=4" \
                                          --slice=myslice.slice \
                                           postgres -D db_test/
```

PostgreSQL should launch successfully, but you still need to give permission for user to edit that slice:

``` shell
user@pc /Work/test> sudo chown -R $USER /sys/fs/cgroup/myslice.slice/
```

And then reload postgres configuration for changes to take place:

``` shell
postgres=# select pg_reload_conf();
 pg_reload_conf
----------------
 t
(1 row)
```


## Usage 

**IMPORTANT:** Extrema and other extensions you want to isolate should be in *shared_preload_libraries*. 

``` shell
> systemd-run --user --scope  -p "Delegate=yes" \
    -p "CPUAccounting=true" \
        -p "MemoryAccounting=true" \
            --slice=postgres \
                postgres -D database/
```

Extrema defines a set of GUC's for each extension in *shared_preload_libraries* (including itself):
- ema.libname_cpu - CPU usage limit
- ema.libname_mem - RAM usage limit in bytes
- ema.libname_swap - VmSwap usage limit in bytes
- ema.libname_numcpu - CPU cores assigned to extension (text, empty if no restrictions)

You can easily configure them:

``` shell
postgres=# alter system set ema.extrema_swap to 8192;
ALTER SYSTEM
postgres=# show ema.extrema_swap ;
 ema.extrema_swap
------------------
 0
(1 row)

postgres=# select pg_reload_conf();
 pg_reload_conf
----------------
 t
(1 row)

postgres=# show ema.extrema_swap ;
 ema.extrema_swap
------------------
 8192
(1 row)
```

## SQL Interface functions 

- ema_lib_info() - get information about managed extensions 

Example:

``` shell
postgres=# select * from ema_lib_info();
 library_name | cpu_usage | ram_usage | vmswap_usage | numcpus
--------------+-----------+-----------+--------------+---------
 testl        |       100 |         0 |            0 |
 extrema      |       100 |  16777216 |         4096 | 0-1
(2 rows)
```

