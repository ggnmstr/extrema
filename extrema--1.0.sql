/* contrib/extrema/extrema--1.0.sql */


CREATE FUNCTION ema_healthcheck()
        RETURNS text
        AS 'MODULE_PATHNAME'
        LANGUAGE C STRICT;

CREATE FUNCTION ema_lib_set_mem(libname text, val integer)
       RETURNS void
       AS 'MODULE_PATHNAME'
       LANGUAGE C STRICT;

CREATE FUNCTION ema_lib_set_cpu(libname text, val integer)
       RETURNS void
       AS 'MODULE_PATHNAME'
       LANGUAGE C STRICT;



CREATE TYPE __ema_lib_info AS (library_name text, cpu_usage float, ram_usage integer);
CREATE  FUNCTION ema_lib_info()
    RETURNS SETOF __ema_lib_info
    AS 'MODULE_PATHNAME'
    LANGUAGE C STRICT;
