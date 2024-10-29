# extrema - EXTension REsource MAnagement in PostgreSQL 

This extension allows user to limit other extensions usage of resources (currently, only CPU, RAM and VmSwap) by adding them to corresponding cgroups. 
These limitations can be easily configured using PostgreSQL's GUC mechanism.

Currently it only supports extensions that are in *shared_preload_libraries*, the extension is also designed to be in *shared_preload_libraries*. 

It relies on a hook that is executed by Postmaster when it registers bgworker. 
Currently extension ships with a patch that adds required hook.

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
 library_name | cpu_usage | ram_usage | vmswap_usage
--------------+-----------+-----------+--------------
 testl        |       100 |   9998336 |      8097792
 extrema      |       100 |  16777216 |            0
(2 rows)
```

