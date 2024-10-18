# extrema - EXTension REsource MAnagement in PostgreSQL 

This extension allows user to limit other extensions usage of resources (currently, only CPU and RAM) by adding them to corresponding cgroups. 

Currently it only supports extensions that are in *shared_preload_libraries*, the extension is also designed to be in *shared_preload_libraries*. 

It relies on a hook that is executed in every bgworker before user-defined code. 
Currently extension ships with a patch that adds required hook.

## Installation

1. Apply a patch to stable PostgreSQL 17:

``` shell
user@pc /postgres/contrib/extrema> git checkout REL_17_STABLE
user@pc /postgres/contrib/extrema> git apply extrema_hook_patch.diff
```

If patch conflitcs with branch, you can reset to specific commit that will work:
**42ce8ba18502d107879776acb32c799e38e59871**
``` shell
user@pc /postgres/contrib/extrema> git checkout REL_17_STABLE
user@pc /postgres/contrib/extrema> git reset --hard 42ce8ba18502d107879776acb32c799e38e59871
user@pc /postgres/contrib/extrema> git apply extrema_hook_patch.diff
```

Don't forget to configure, make and install PostgreSQL after you apply the patch to source code.


2. Install extension: 
``` shell 
user@pc /postgres/contrib/extrema> make
user@pc /postgres/contrib/extrema> make install
```

In SQL interface:
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

## SQL Interface functions 

- ema_lib_info() - get information about managed extensions 
- ema_lib_set_mem(libname text, val integer) - set RAM limit for extension's bgworkers
- ema_lib_set_cpu(libname text, val integer) - set CPU usage limit for extension's bgworkers
