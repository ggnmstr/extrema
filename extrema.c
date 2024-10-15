#include "postgres.h"
#include "c.h"
#include "common/file_perm.h"
#include "lib/ilist.h"
#include "nodes/pg_list.h"
#include "port.h"
#include "postmaster/bgworker_internals.h"
#include "utils/builtins.h"
#include "fmgr.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/palloc.h"
#include "utils/varlena.h"
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include "funcapi.h"
#include <unistd.h>
PG_MODULE_MAGIC;


// some defines to avoid magic const buffers
#ifdef PATH_MAX
	#define CGROUP_PATH_LEN PATH_MAX
#else
	#define CGROUP_PATH_LEN 4096
#endif

#define LIBNAME_LEN 256
#define CONTROLLER_VALUE_LEN 1024



typedef struct reg_entry {
	char libname[LIBNAME_LEN];
	int cpu_usage;
	size_t ram_usage;
} reg_entry;


static int set_lib_controller_value(const char *libname, const char *controller, const char *value, size_t vlen);
static int healthcheck_internal();
static void bgw_isolate(BackgroundWorker *bgworkerEntry);
static int lib_create_cgroup(const char *libname, reg_entry *entry);
static int prepare_cgroup_subtree();
static int lib_set_mem(const char *libname, size_t val);
static int lib_set_cpu(const char *libname, int weight);
static reg_entry *find_entry(const char *libname);
static int get_pm_cg();


int pagesize;

// TODO change to hashmap
List *library_list;


// postmaster cgroup full path
char pm_cg_fp[CGROUP_PATH_LEN];

BgwBeforeUserCode_hook_type old_bgworker_hook;

MemoryContext oldctx;

// XXX
// https://unix.stackexchange.com/questions/754605/how-to-add-pid-inside-cgroup-procs-with-non-root-privileges-in-cgroup-v2-in-ubun
void
_PG_init(void)
{
	int health;
	char *res;
	reg_entry *cur_entry;


	if (get_pm_cg() != 0)
	{
		elog(ERROR,"Error getting Postmaster's cgroup info \
			 It should be lauched in user cgroup.");
	}


	health = healthcheck_internal();
	if (health != 0)
	{
		switch (health)
		{
			case -1:
				elog(ERROR,"Can't access cgroup postgres_bgworkers. Assert that user has rights to edit it.");
				break;
			case -5:
				elog(ERROR,"postgres_bgworkers cgroup should have following controllers: cpu cpuset memory");
				break;
			default:
				elog(ERROR,"Unknown error occured.");
				break;
		}
		return;
	}
	elog(LOG,"Health check passed, initializing bgworker_cgroups extension");

	pagesize = getpagesize();


	old_bgworker_hook = BgwBeforeUserCode_hook;
	BgwBeforeUserCode_hook = bgw_isolate;

	if (prepare_cgroup_subtree() != 0)
	{
		elog(ERROR,"Error ;c");
		return;
	}


	res = GetConfigOption("shared_preload_libraries",true,false);
	if (res == NULL){
		elog(LOG,"LIBRARIES NOT FOUND :C");
		return;
	}
	elog(LOG,"LIBS FOUND: \'%s\'",res);
	{
		/*
		 * For each library found in shared_preload_libraries
		 * Create it's own cgroup and allocate entry in register (List)
		 */
		char *library_name = strtok(res,", ");
		while (library_name != NULL)
		{
			elog(LOG,"LIBRARY NAME \'%s\'",library_name);

			// XXX suspicious context switching.
			// do we really need it?
			oldctx = MemoryContextSwitchTo(TopMemoryContext);

			cur_entry = palloc_object(reg_entry);
			strcpy(cur_entry->libname,library_name);

			library_list = lappend(library_list,cur_entry);

			if (lib_create_cgroup(library_name,cur_entry) != 0)
			{
				elog(ERROR,"Error defining libs");
			}

			MemoryContextSwitchTo(oldctx);

			library_name = strtok(NULL, ", ");
		}
	}




}

/*
 * Reads full path to postgres.slice (created by user or systemd)
 * cgroup into pm_cg_fp
 *
 * Returns 0 on success.
*/
static int get_pm_cg()
{

	char pm_cg[CGROUP_PATH_LEN];
	int fd;
	ssize_t bread;

	fd = open("/proc/self/cgroup",O_RDONLY);
	if (fd == -1)
	{
		return -1;
	}
	if ( ( bread = read(fd, pm_cg, sizeof(pm_cg)) ) < 0)
	{
		close(fd);
		return -2;
	}

	// we may read some trash after actual cgroup data
	// so find first \n symbol and end string there
	{
		char *fn = strchr(pm_cg, '\n');
		if (fn)
		{
			*fn = '\0';
		}
	}


	// XXX
	// All the stuff in this extension related to cgroups is kinda hardcoded
	// because of the way it was tested.
	// Because I launched Postgres using systemd-run under postgres.slice cgroup,
	// full path to postmaster's cgroup looks like this:
	//
	// /sys/fs/cgroup/user.slice/..../..../postgres.slice/abcd-run-1234
	//
	// We can't create new valid cgroups in that cgroup,
	// we want to create extension cgroups in postgres.slice cgroup.
	// So for that we cut that last part off the full path by
	// finding the last '/' symbol and changing it to null-terminator.
	{
		char *scp = strrchr(pm_cg, '/');
		if (scp)
		{
			*scp = '\0';
		}
	}

	// pm_cg+4 to skip these four first symbols: "0::/"
	sprintf(pm_cg_fp,"/sys/fs/cgroup/%s",pm_cg+4);
	elog(LOG, "PM CG FULLPATH: %s",pm_cg_fp);
	return 0;
}

/*
 * Isolates extension's bgworker by adding
 * its pid to corresponding cgroup's cgroup.procs file
 *
 * This routine is called in every bgworker
 * before executing user-defined code
 * (assigned as hook in _PG_init)
 */

static void bgw_isolate(BackgroundWorker *bgw_entry)
{
	// max pid value is less than 32 digit
	// allocate some more just in case
	char spid[32];
	int printed;
	const char *libname = bgw_entry->bgw_library_name;
	if (old_bgworker_hook){
		old_bgworker_hook(bgw_entry);
	}
	printed = sprintf(spid,"%lu",getpid());
	elog(LOG,"BGW by %s, my pid: %lu",libname,getpid());
	printed = set_lib_controller_value(libname,"cgroup.procs",spid , printed);
}


static int
set_lib_controller_value(const char *libname, const char *controller, const char *value, size_t vlen)
{
	char cpath[CGROUP_PATH_LEN];
	int fd;
	sprintf(cpath, "%s/%s/%s",pm_cg_fp, libname,controller);

	fd = open(cpath,O_WRONLY | O_APPEND);
	if (fd < 0)
	{
		int e = errno;
		elog(LOG,"set_lib_controller open lib %s controller %s error: %s",libname,controller,strerror(e));
		return -1;
	}
	if (write(fd,value,vlen) < 0)
	{
		int e = errno;
		elog(LOG,"set_lib_controller write error: %s",strerror(e));
		close(fd);
		return -2;
	}

	close(fd);
	return 0;
}

/*
 * Creates cgroup for given library
 * and sets some default values for it
 *
 * Returns 0 on success.
 */

// FIXME "entry" is not used
// change interaction method between user and lib
static int
lib_create_cgroup(const char *libname, reg_entry *entry)
{
	char cgroup_path[CGROUP_PATH_LEN];

	sprintf(cgroup_path, "%s/%s",pm_cg_fp, libname);


	// FIXME;
	// perhaps, we should firstly check that these directories exist
	// before we mkdir them?
	if (pg_mkdir_p(cgroup_path, pg_dir_create_mode) < 0){
		elog(LOG, "ERROR CREATING CGROUP FOR %s",libname);
		return -1;
	}
	elog(LOG, "CGROUP FOR %s CREATED SUCCESSFULLY",libname);

	if (lib_set_mem(libname, 16384) != 0)
	{
		return -2;
	}

	if (lib_set_cpu(libname, 100) != 0)
	{
		return -3;
	}


	return 0;

}

/*
* Finds corresponding reg_entry to the library name.
*
* Returns pointer to that entry on success,
* NULL otherwise.
*/
static reg_entry *find_entry(const char *libname)
{

	ListCell *lc;
	foreach(lc, library_list)
	{
		reg_entry *entry = (reg_entry *) lfirst(lc);
		const char *ln = entry->libname;

		if (strcmp(ln, libname) == 0)
		{
			return entry;
		}
	}

	return NULL;
}

PG_FUNCTION_INFO_V1(ema_lib_set_cpu);
Datum
ema_lib_set_cpu(PG_FUNCTION_ARGS)
{
	const char *libname = text_to_cstring(PG_GETARG_TEXT_P(0));
	int weight = PG_GETARG_INT64(1);
	lib_set_cpu(libname, weight);
	PG_RETURN_VOID();
}

static int lib_set_cpu(const char *libname, int weight)
{
	char sval[CONTROLLER_VALUE_LEN];
	int printed;
	reg_entry *entry;

	elog(LOG, "lib_set_cpu: setting %s to %lu",libname,weight);
	printed = sprintf(sval,"%d",weight);
	if (set_lib_controller_value(libname,"cpu.weight",sval,printed) != 0){
		return -1;
	}
	entry = find_entry(libname);
	if (entry == NULL)
	{
		return -1;
	}
	entry->cpu_usage = weight;
	return 0;

}


PG_FUNCTION_INFO_V1(ema_lib_set_mem);
Datum
ema_lib_set_mem(PG_FUNCTION_ARGS)
{
	const char *libname = text_to_cstring(PG_GETARG_TEXT_P(0));
	int size = PG_GETARG_INT64(1);
	lib_set_mem(libname, size);
	PG_RETURN_VOID();

}

static int
lib_set_mem(const char *libname, size_t val)
{
	char sval[CONTROLLER_VALUE_LEN];
	int printed;
	reg_entry *entry;

	elog(LOG, "lib_set_mem: setting %s to %lu",libname,val);
	printed = sprintf(sval,"%d",val);
	if (set_lib_controller_value(libname,"memory.max",sval,printed) != 0){
		return -1;
	}
	entry = find_entry(libname);
	if (entry == NULL)
	{
		return -1;
	}

	/*
	 * memory.max in cgroup is floored to N*PAGESIZE of system.
	 * So to keep the actual data in registry
	 * we should also floor the number.
	 */
	entry->ram_usage = (val / pagesize) * (pagesize);
	return 0;
}


PG_FUNCTION_INFO_V1(ema_lib_info);
Datum
ema_lib_info(PG_FUNCTION_ARGS)
{
    FuncCallContext     *funcctx;
    int                  call_cntr;
    int                  max_calls;
    TupleDesc            tupdesc;
    AttInMetadata       *attinmeta;

    /* stuff done only on the first call of the function */
    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext   oldcontext;

        /* create a function context for cross-call persistence */
        funcctx = SRF_FIRSTCALL_INIT();

        /* switch to memory context appropriate for multiple function calls */
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        /* total number of tuples to be returned */
        funcctx->max_calls = list_length(library_list);

        /* Build a tuple descriptor for our result type */
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function returning record called in context "
                            "that cannot accept type record")));

        /*
         * generate attribute metadata needed later to produce tuples from raw
         * C strings
         */
        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;

        MemoryContextSwitchTo(oldcontext);
    }

    /* stuff done on every call of the function */
    funcctx = SRF_PERCALL_SETUP();

    call_cntr = funcctx->call_cntr;
    max_calls = funcctx->max_calls;
    attinmeta = funcctx->attinmeta;

    if (call_cntr < max_calls)    /* do when there is more left to send */
    {
        char       **values;
        HeapTuple    tuple;
        Datum        result;
		reg_entry *entry;


		entry = list_nth_node(reg_entry, library_list, call_cntr);
        /*
         * Prepare a values array for building the returned tuple.
         * This should be an array of C strings which will
         * be processed later by the type input functions.
         */
		 // lib name, cpu usage, ram usage
        values = (char **) palloc(3 * sizeof(char *));
        values[0] = (char *) palloc(128 * sizeof(char));
        values[1] = (char *) palloc(16 * sizeof(char));
        values[2] = (char *) palloc(16 * sizeof(char));

        snprintf(values[0], 16, "%s", entry->libname);
        sprintf(values[1], "%d", entry->cpu_usage);
        sprintf(values[2], "%zu", entry->ram_usage);

        /* build a tuple */
        tuple = BuildTupleFromCStrings(attinmeta, values);

        /* make the tuple into a datum */
        result = HeapTupleGetDatum(tuple);

        /* clean up (this is not really necessary) */
        pfree(values[0]);
        pfree(values[1]);
        pfree(values[2]);
        pfree(values);

        SRF_RETURN_NEXT(funcctx, result);
    }
    else    /* do when there is no more left */
    {
        SRF_RETURN_DONE(funcctx);
    }

}




/*
** Healthcheck wrapped in SQL interface function.
*/
PG_FUNCTION_INFO_V1(ema_healthcheck);
Datum
ema_healthcheck(PG_FUNCTION_ARGS)
{
	int result;

	result = healthcheck_internal();
	if (result == 0){
		PG_RETURN_TEXT_P(cstring_to_text("Everything is fine!"));
	} else if (result == -1){
		PG_RETURN_TEXT_P(cstring_to_text("Can't access postgres' cgroup. Assert that user has rights to edit it."));
	} else {
		PG_RETURN_TEXT_P(cstring_to_text("Error, are you sure that cgroup postgres exists?"));
	}
	PG_RETURN_TEXT_P(cstring_to_text("Everything is fine!"));
}

/*
** This function checks following requirements:
** 1. cgroup of postgres (postgres.slice) exists
** 2. User has rights to edit it
** 3. It has required cgroup controllers (cpuset,cpu,memory)
**
** Returns 0 on success, negative value otherwise.
 */
static int healthcheck_internal()
{
	char path[CGROUP_PATH_LEN];
	int fd;
	size_t bread;



	if (access(pm_cg_fp, W_OK) != 0){
		if (errno == EACCES){
			return -1;
		} else {
			return -2;
		}
	}
	sprintf(path,"%s/cgroup.controllers",pm_cg_fp);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	if ((bread = read(fd, path, sizeof(path))) == -1){
		close(fd);
		return -3;
	}
	close(fd);

	// we may read some trash after actual cgroup data
	// so find first \n symbol and end string there
	{
		char *fn = strchr(path, '\n');
		if (fn)
		{
			*fn = '\0';
		}
	}


	elog(LOG,"CGROUP CONTROLLERS: \'%s\'",path);

	// we need "cpuset", "cpu", "memory"
	{
		int controllers = 0;
		char *controller = strtok(path," ");
		while (controller != NULL)
		{
			if (strcmp(controller, "cpuset") == 0 ||
				strcmp(controller, "cpu") == 0 ||
				strcmp(controller,"memory") == 0)
			{
				controllers++;
			}

			controller = strtok(NULL," ");
		}
		// TODO IDK if we need cpuset?
		if (controllers < 2)
		{
			return -5;
		}
	}


	return 0;
}


static int prepare_cgroup_subtree()
{
	const char add_cpuset[] = "+cpuset\n";
	const char add_cpu[] = "+cpu\n";
	const char add_memory[] = "+memory\n";
	int fd;
	char cg_subtree_path[CGROUP_PATH_LEN];
	sprintf(cg_subtree_path,"%s/cgroup.subtree_control",pm_cg_fp);
	elog(LOG,"OPENING %s TO PREPARE",cg_subtree_path);
	fd = open(cg_subtree_path,O_WRONLY | O_APPEND);
	if (fd < 0)
	{
		int e = errno;
		elog(ERROR,"ERROR IN OPEN: %s",strerror(e));
		return -1;
	}
	// FIXME for now we blocked adding cpuset
	// because it is not initially in our postmaster cgroup.
	/* if (write(fd,add_cpuset,sizeof(add_cpuset)) < 0) */
	/* { */
	/* 	int e = errno; */
	/* 	elog(ERROR,"ERROR IN WRITE cpuset: %s",strerror(e)); */
	/* 	close(fd); */
	/* 	return -2; */
	/* } */
	if (write(fd,add_cpu,sizeof(add_cpu)) < 0)
	{
		int e = errno;
		elog(ERROR,"ERROR IN WRITE cpu: %s",strerror(e));
		close(fd);
		return -2;
	}
	if (write(fd,add_memory,sizeof(add_memory)) < 0)
	{
		int e = errno;
		elog(ERROR,"ERROR IN WRITE memory: %s",strerror(e));
		close(fd);
		return -2;
	}
	close(fd);
	return 0;
}