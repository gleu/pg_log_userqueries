/*-------------------------------------------------------------------------
 *
 * pg_log_userqueries.c
 *		Log statement according to the user.
 *
 *
 * Copyright (c) 2011-2023, Guillaume Lelarge (Dalibo),
 * guillaume.lelarge@dalibo.com
 *
 *-------------------------------------------------------------------------
 */
#ident "pg_log_userqueries version 1.4"

#include "postgres.h"

#include <unistd.h>
#include <regex.h>
#include <syslog.h>
#include <sys/stat.h>
#include <time.h>
/* to log statement duration */
#include <utils/timestamp.h>
#include <access/xact.h>

#include <storage/proc.h>

#if PG_VERSION_NUM >= 140000
// to log query_id
#include <utils/backend_status.h>
#endif

/*
 * We won't use PostgreSQL regexps,
 * and as they redefine some system regexps types, we make sure we don't
 * redefine them
 */
#define _REGEX_H_

#include "funcapi.h"
#include "tcop/utility.h"
#include "libpq/libpq-be.h" /* For Port▸▸   ▸   ▸   ▸   ▸   */
#include "miscadmin.h"      /* For MyProcPort▸  ▸   ▸   ▸   */

PG_MODULE_MAGIC;

#ifndef PG_SYSLOG_LIMIT
#define PG_SYSLOG_LIMIT 1024
#endif

#ifndef LOCAL_DEBUG
#define LOCAL_DEBUG 1
#endif

/*---- Local variables ----*/
static const struct config_enum_entry server_message_level_options[] = {
	{"debug", DEBUG2, true},
	{"debug5", DEBUG5, false},
	{"debug4", DEBUG4, false},
	{"debug3", DEBUG3, false},
	{"debug2", DEBUG2, false},
	{"debug1", DEBUG1, false},
	{"info", INFO, false},
	{"notice", NOTICE, false},
	{"warning", WARNING, false},
	{"error", ERROR, false},
	{"log", LOG, false},
	{"fatal", FATAL, false},
	{"panic", PANIC, false},
	{NULL, 0, false}
};

static const struct config_enum_entry log_destination_options[] = {
	{"stderr", 1, false},
	{"syslog", 2, false},
	{NULL, 0}
};

static const struct config_enum_entry syslog_facility_options[] = {
	{"local0", LOG_LOCAL0, false},
	{"local1", LOG_LOCAL1, false},
	{"local2", LOG_LOCAL2, false},
	{"local3", LOG_LOCAL3, false},
	{"local4", LOG_LOCAL4, false},
	{"local5", LOG_LOCAL5, false},
	{"local6", LOG_LOCAL6, false},
	{"local7", LOG_LOCAL7, false},
	{NULL, 0}
};


static int     log_level = WARNING;
static char *  log_label = NULL;
static char *  log_user = NULL;
static char *  log_user_blacklist = NULL;
static char *  log_query_id = NULL;
static char *  log_query_id_blacklist = NULL;
static char *  log_db = NULL;
static char *  log_db_blacklist = NULL;
static char *  log_addr = NULL;
static char *  log_addr_blacklist = NULL;
static char *  log_query = NULL;
static char *  log_query_blacklist = NULL;
static char *  log_app = NULL;
static char *  log_app_blacklist = NULL;
static bool    log_superusers = false;
static int     regex_flags = REG_NOSUB;
static regex_t usr_regexv;
static regex_t usr_bl_regexv;
static regex_t db_regexv;
static regex_t db_bl_regexv;
static regex_t addr_regexv;
static regex_t addr_bl_regexv;
static regex_t app_regexv;
static regex_t app_bl_regexv;
static regex_t query_regexv;
static regex_t query_bl_regexv;
static regex_t query_id_regexv;
static regex_t query_id_bl_regexv;
static bool    openlog_done = false;
static char *  syslog_ident = NULL;
static int     log_destination = 1; /* aka stderr */
static int     syslog_facility = LOG_LOCAL0;
static int     syslog_level = LOG_NOTICE;
static time_t  ref_time = 0;
static char *  file_switchoff = NULL;
static bool    switch_off = false;
static int     time_switchoff = 300;
static bool    match_all = false;
static bool    enable_log_duration = false;

/* Saved hook values in case of unload */
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
#if PG_VERSION_NUM >= 90000
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
#endif


/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

static void pgluq_ExecutorEnd(QueryDesc *queryDesc);
#if PG_VERSION_NUM >= 140000
static void pgluq_ProcessUtility(PlannedStmt *pstmt,
      const char *queryString,
      bool readOnlyTree,
      ProcessUtilityContext context,
      ParamListInfo params,
      QueryEnvironment *queryEnv,
      DestReceiver *dest, QueryCompletion *qc);
#elif PG_VERSION_NUM >= 130000
static void pgluq_ProcessUtility(PlannedStmt *pstmt,
			  const char *queryString, ProcessUtilityContext context, ParamListInfo params,
					QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc);
#elif PG_VERSION_NUM >= 100000
static void pgluq_ProcessUtility(PlannedStmt *pstmt,
			  const char *queryString, ProcessUtilityContext context, ParamListInfo params,
					QueryEnvironment *queryEnv, DestReceiver *dest, char *completionTag);
#elif PG_VERSION_NUM >= 90300
static void pgluq_ProcessUtility(Node *parsetree,
			  const char *queryString, ProcessUtilityContext context, ParamListInfo params,
					DestReceiver *dest, char *completionTag);
#elif PG_VERSION_NUM >= 90000
static void pgluq_ProcessUtility(Node *parsetree,
			  const char *queryString, ParamListInfo params, bool isTopLevel,
					DestReceiver *dest, char *completionTag);
#endif
#if PG_VERSION_NUM >= 140000
static bool pgluq_check_log(PlannedStmt *pstmt);
#else
static bool pgluq_check_log(void);
#endif
static void pgluq_log(const char *query);
static void write_syslog(int level, char *line);
static char *log_prefix(const char *query);
static bool check_switchoff(void);
static bool check_time_switch(void);

extern char *get_database_name(Oid dbid);
extern int pg_mbcliplen(const char *mbstr, int len, int limit);

static bool pgluq_checkitem(const char *item,
				const char *log_wl, regex_t *regex_wl,
				const char *log_bl, regex_t *regex_bl);

#if PG_VERSION_NUM >= 140000
static bool pgluq_checkBLitem(const char *item,
				const char *log_bl, regex_t *regex_bl);

static bool pgluq_checkWLitem(const char *item,
				const char *log_wl, regex_t *regex_wl);
#endif

/*
 * Module load callback
 */
void
_PG_init(void)
{
	/*
	 * In order to create our shared memory area, we have to be loaded via
	 * shared_preload_libraries.  If not, fall out without hooking into any of
	 * the main system.  (We don't throw error here because it seems useful to
	 * allow the pgluq_log functions to be created even when the module
	 * isn't active.  The functions must protect themselves against
	 * being called then, however.)
	 */
	if (!process_shared_preload_libraries_in_progress)
		return;

	/*
 	 * Define (or redefine) custom GUC variables.
	 */

	DefineCustomStringVariable( "pg_log_userqueries.log_query_id",
				"Log statement according to the given query_id.",
				NULL,
				&log_query_id,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );

   DefineCustomStringVariable( "pg_log_userqueries.log_query_id_blacklist",
				"Do not log statement with query_id in this list.",
				NULL,
				&log_query_id_blacklist,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );

	DefineCustomStringVariable( "pg_log_userqueries.log_label",
				"Label in front of the user query.",
				NULL,
				&log_label,
				"pg_log_userqueries",
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );


   DefineCustomEnumVariable( "pg_log_userqueries.log_level",
				"Selects level of log (same options than log_min_messages).",
				NULL,
				&log_level,
				log_level,
				server_message_level_options,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
   DefineCustomStringVariable( "pg_log_userqueries.log_user",
				"Log statement according to the given user.",
				NULL,
				&log_user,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_user_blacklist",
				"Do not log statement from user in this list.",
				NULL,
				&log_user_blacklist,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_db",
				"Log statement according to the given database.",
				NULL,
				&log_db,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_db_blacklist",
				"Do not log statement in databases in this list.",
				NULL,
				&log_db_blacklist,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_addr",
				"Log statement according to the given client IP address.",
				NULL,
				&log_addr,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_addr_blacklist",
				"Do not log statement from addresses in this list.",
				NULL,
				&log_addr_blacklist,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_app",
				"Log statement according to the given application name.",
				NULL,
				&log_app,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_app_blacklist",
				"Do not log statement from the applications in this list.",
				NULL,
				&log_app_blacklist,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
   DefineCustomEnumVariable( "pg_log_userqueries.log_destination",
				"Selects log destination (either stderr or syslog).",
				NULL,
				&log_destination,
				log_destination,
				log_destination_options,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
   DefineCustomEnumVariable( "pg_log_userqueries.syslog_facility",
				"Selects syslog level of log (same options than PostgreSQL syslog_facility).",
				NULL,
				&syslog_facility,
				syslog_facility,
				syslog_facility_options,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
   DefineCustomStringVariable( "pg_log_userqueries.syslog_ident",
				"Select syslog program identity name.",
				NULL,
				&syslog_ident,
				"pg_log_userqueries",
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
	DefineCustomBoolVariable( "pg_log_userqueries.log_superusers",
				"Enable log of superusers.",
				NULL,
				&log_superusers,
				false,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
    DefineCustomStringVariable( "pg_log_userqueries.file_switchoff",
				"If file exists, owned by root with the right properties, switch off the trace log.",
				NULL,
				&file_switchoff,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
    DefineCustomIntVariable( "pg_log_userqueries.time_switchoff",
				"Time interval between file_switchoff existence checks.",
				NULL,
				&time_switchoff,
				300, /* 5 min by default */
				30,
				3600,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
   DefineCustomStringVariable( "pg_log_userqueries.log_query",
				"Log statement according to the given regular expression.",
				NULL,
				&log_query,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
    DefineCustomBoolVariable( "pg_log_userqueries.match_all",
				"Log statement only when all defined conditions for log_user, log_db, log_addr, log_app and log_query match.",
				NULL,
				&match_all,
				false,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
   DefineCustomStringVariable( "pg_log_userqueries.log_query_blacklist",
				"Do not log statement in this list.",
				NULL,
				&log_query_blacklist,
				NULL,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );
	DefineCustomBoolVariable( "pg_log_userqueries.log_duration",
				"Enable log of query duration.",
				NULL,
				&enable_log_duration,
				false,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);

	/* Add support to extended regex search */
	regex_flags |= REG_EXTENDED;

	/* Compile regexp for query_id */
	if (log_query_id != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_query_id) + 5));
		sprintf(tmp, "^(%s)$", log_query_id);
		if (regcomp(&query_id_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid query_id pattern %s", tmp)));
			log_query_id = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for query_id blacklist */
	if (log_query_id_blacklist != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_query_id_blacklist) + 5));
		sprintf(tmp, "^(%s)$", log_query_id_blacklist);
		if (regcomp(&query_id_bl_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid query_id blacklist pattern %s", tmp)));
			log_query_id_blacklist = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for user name */
	if (log_user != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_user) + 5));
		sprintf(tmp, "^(%s)$", log_user);
		if (regcomp(&usr_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid user pattern %s", tmp)));
			log_user = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for user name blacklist */
	if (log_user_blacklist != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_user_blacklist) + 5));
		sprintf(tmp, "^(%s)$", log_user_blacklist);
		if (regcomp(&usr_bl_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid user blacklist pattern %s", tmp)));
			log_user_blacklist = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for db name */
	if (log_db != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_db) + 5));
		sprintf(tmp, "^(%s)$", log_db);
		if (regcomp(&db_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid database pattern %s", tmp)));
			log_db = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for db name blacklist */
	if (log_db_blacklist != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_db_blacklist) + 5));
		sprintf(tmp, "^(%s)$", log_db_blacklist);
		if (regcomp(&db_bl_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid database blacklist pattern %s", tmp)));
			log_db_blacklist = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for inet addr */
	if (log_addr != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_addr) + 5));
		sprintf(tmp, "^(%s)$", log_addr);
		if (regcomp(&addr_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid address pattern %s", tmp)));
			log_addr = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for inet addr blacklist */
	if (log_addr_blacklist != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_addr_blacklist) + 5));
		sprintf(tmp, "^(%s)$", log_addr_blacklist);
		if (regcomp(&addr_bl_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid address blacklist pattern %s", tmp)));
			log_addr_blacklist = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for application name */
	if (log_app != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_app) + 5));
		sprintf(tmp, "^(%s)$", log_app);
		if (regcomp(&app_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid application name pattern %s", tmp)));
			log_app = NULL;
		}
		pfree(tmp);
	}
	/* Compile regexp for application name blacklist */
	if (log_app_blacklist != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_app_blacklist) + 5));
		sprintf(tmp, "^(%s)$", log_app_blacklist);
		if (regcomp(&app_bl_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid application name blacklist pattern %s", tmp)));
			log_app_blacklist = NULL;
		}
		pfree(tmp);
	}
	/* Compile rexgep to log statement */
	if (log_query != NULL)
	{
		if (regcomp(&query_regexv, log_query, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid statement regexp pattern %s", log_query)));
			log_query = NULL;
		}
	}
	/* Compile rexgep from the log statement blacklist */
	if (log_query_blacklist != NULL)
	{
		if (regcomp(&query_bl_regexv, log_query_blacklist, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid statement regexp blacklist pattern %s", log_query_blacklist)));
			log_query_blacklist = NULL;
		}
	}

	/* Open syslog descriptor, if required */
	if (log_destination == 2 /* aka syslog */)
	{
		/* Find syslog_level according to the user log_level setting */
		switch (log_level)
		{
			case DEBUG5:
			case DEBUG4:
			case DEBUG3:
			case DEBUG2:
			case DEBUG1:
				syslog_level = LOG_DEBUG;
				break;
			case LOG:
			case COMMERROR:
			case INFO:
				syslog_level = LOG_INFO;
				break;
			case NOTICE:
			case WARNING:
				syslog_level = LOG_NOTICE;
				break;
			case ERROR:
				syslog_level = LOG_WARNING;
				break;
			case FATAL:
				syslog_level = LOG_ERR;
				break;
			case PANIC:
			default:
				syslog_level = LOG_CRIT;
				break;
		}
		/* Open syslog descriptor */
		openlog(syslog_ident, LOG_PID | LOG_NDELAY | LOG_NOWAIT, syslog_facility);
		openlog_done = true;
	}

	/*
	 * Install hooks.
	 */
	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = pgluq_ExecutorEnd;
#if PG_VERSION_NUM >= 90000
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = pgluq_ProcessUtility;
#endif
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Close syslog descriptor, if required */
	if (openlog_done)
	{
		closelog();
		openlog_done = false;
	}

	/* Uninstall hooks. */
	ExecutorEnd_hook = prev_ExecutorEnd;
#if PG_VERSION_NUM >= 90000
	ProcessUtility_hook = prev_ProcessUtility;
#endif

	/* free the memory allocated by regcomp.
	 * This is safe since we made sure the log_* parameters where reset
	 * to NULL in case regcomp fails.
	 */
	if (log_user != NULL)
		regfree(&usr_regexv);
	if (log_user_blacklist != NULL)
		regfree(&usr_bl_regexv);
	if (log_db != NULL)
		regfree(&db_regexv);
	if (log_db_blacklist != NULL)
		regfree(&db_bl_regexv);
	if (log_addr != NULL)
		regfree(&addr_regexv);
	if (log_addr_blacklist != NULL)
		regfree(&addr_bl_regexv);
	if (log_app != NULL)
		regfree(&app_regexv);
	if (log_app_blacklist != NULL)
		regfree(&app_bl_regexv);
	if (log_query != NULL)
		regfree(&query_regexv);
	if (log_query_blacklist != NULL)
		regfree(&query_bl_regexv);
	if (log_query_id != NULL)
		regfree(&query_id_regexv);
	if (log_query_id_blacklist != NULL)
			regfree(&query_id_bl_regexv);
 }

/*
 * ExecutorEnd hook: store results if needed
 */
static void
pgluq_ExecutorEnd(QueryDesc *queryDesc)
{
#if PG_VERSION_NUM >= 140000
    if (pgluq_check_log(queryDesc->plannedstmt))
#else
    if (pgluq_check_log())
#endif
		pgluq_log(queryDesc->sourceText);

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*
 * ProcessUtility hook
 * (only available from 9.0 releases)
 */
#if PG_VERSION_NUM >= 140000
static void pgluq_ProcessUtility(PlannedStmt *pstmt,
      const char *queryString,
      bool readOnlyTree,
      ProcessUtilityContext context,
      ParamListInfo params,
      QueryEnvironment *queryEnv,
      DestReceiver *dest, QueryCompletion *qc)
{
		PG_TRY();
		{
			if (prev_ProcessUtility)
				prev_ProcessUtility(pstmt, queryString, readOnlyTree, context,
									params, queryEnv, dest, qc);
			else
				standard_ProcessUtility(pstmt, queryString, readOnlyTree, context,
										params, queryEnv, dest, qc);
		}
		PG_CATCH();
		{
			PG_RE_THROW();
		}
		PG_END_TRY();

	if (pgluq_check_log(pstmt))
		pgluq_log(queryString);
}
#elif PG_VERSION_NUM >= 130000
static void
pgluq_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
					ProcessUtilityContext context, ParamListInfo params,
					QueryEnvironment *queryEnv, DestReceiver *dest,
					QueryCompletion *qc)
{
		PG_TRY();
		{
			if (prev_ProcessUtility)
				prev_ProcessUtility(pstmt, queryString, context,
									params, queryEnv, dest, qc);
			else
				standard_ProcessUtility(pstmt, queryString, context,
										params, queryEnv, dest, qc);
		}
		PG_CATCH();
		{
			PG_RE_THROW();
		}
		PG_END_TRY();

	if (pgluq_check_log())
		pgluq_log(queryString);
}
#elif PG_VERSION_NUM >= 100000
static void
pgluq_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
					ProcessUtilityContext context, ParamListInfo params,
					QueryEnvironment *queryEnv, DestReceiver *dest,
					char *completionTag)
{
		PG_TRY();
		{
			if (prev_ProcessUtility)
				prev_ProcessUtility(pstmt, queryString, context,
									params, queryEnv, dest, completionTag);
			else
				standard_ProcessUtility(pstmt, queryString, context,
										params, queryEnv, dest, completionTag);
		}
		PG_CATCH();
		{
			PG_RE_THROW();
		}
		PG_END_TRY();

		if (pgluq_check_log())
			pgluq_log(queryString);
}
#elif PG_VERSION_NUM >= 90300
static void
pgluq_ProcessUtility(Node *parsetree, const char *queryString,
					ProcessUtilityContext context, ParamListInfo params,
					DestReceiver *dest, char *completionTag)
{
		PG_TRY();
		{
			if (prev_ProcessUtility)
				prev_ProcessUtility(parsetree, queryString, context,
									params, dest, completionTag);
			else
				standard_ProcessUtility(parsetree, queryString, context,
										params, dest, completionTag);
		}
		PG_CATCH();
		{
			PG_RE_THROW();
		}
		PG_END_TRY();

    if (pgluq_check_log())
		pgluq_log(queryString);
}
#elif PG_VERSION_NUM >= 90000
static void
pgluq_ProcessUtility(Node *parsetree, const char *queryString,
					ParamListInfo params, bool isTopLevel,
					DestReceiver *dest, char *completionTag)
{
		PG_TRY();
		{
			if (prev_ProcessUtility)
				prev_ProcessUtility(parsetree, queryString, params,
									isTopLevel, dest, completionTag);
			else
				standard_ProcessUtility(parsetree, queryString, params,
										isTopLevel, dest, completionTag);
		}
		PG_CATCH();
		{
			PG_RE_THROW();
		}
		PG_END_TRY();

    if (pgluq_check_log())
		pgluq_log(queryString);
}
#endif

/*
 * Check an item
 */
static bool pgluq_checkitem(const char *item,
				const char *log_wl, regex_t *regex_wl,
				const char *log_bl, regex_t *regex_bl)
{
	bool has_passed_wl = true;
	bool has_passed_bl = true;

	if ((log_wl != NULL) && (regexec(regex_wl, item, 0, 0, 0) != 0))
		has_passed_wl = false;

	if ((log_bl != NULL) && (regexec(regex_bl, item, 0, 0, 0) == 0))
		has_passed_bl= false;

	if (! has_passed_wl || ! has_passed_bl) {
 		return false;
	}
 	return true;
}

#if PG_VERSION_NUM >= 140000
/*
 * Check an item and a blacklist
 */
static bool pgluq_checkBLitem(const char *item,
				const char *log_bl, regex_t *regex_bl)
{
	bool has_passed_bl = true;

	if ((log_bl != NULL) && (regexec(regex_bl, item, 0, 0, 0) == 0))
		has_passed_bl= false;

	return has_passed_bl;
}

/*
 * Check an item and a whitelist
 */
static bool pgluq_checkWLitem(const char *item,
				const char *log_wl, regex_t *regex_wl)
{
	bool has_passed_wl = true;

	if ((log_wl != NULL) && (regexec(regex_wl, item, 0, 0, 0) != 0))
		has_passed_wl = false;

	return has_passed_wl;
}
#endif

/*
 * Check if we should log
 */

/* I need a PlannedStmt to get the query_id */

#if PG_VERSION_NUM >= 140000
static bool pgluq_check_log(PlannedStmt *pstmt)
#else
static bool pgluq_check_log()
#endif
{
	/* object's name */
	char *dbname  = NULL;
	char *username = NULL;
	char *addr = NULL;
	char *appname  = NULL;
	bool ret = false;
	bool rc;

#if PG_VERSION_NUM >= 140000
   char *query_id = NULL;
   uint64 int_query_id = UINT64CONST(0);
   char buf[256];
#endif

	if (check_switchoff())
		return false;

/* query_id exists since v14 */
#if PG_VERSION_NUM >= 140000
	int_query_id = pstmt->queryId;
   snprintf(buf, sizeof buf, "%lu", int_query_id);
   query_id = pstrdup((const char*) buf);
#endif

#if PG_VERSION_NUM >= 90602
	/*
	 * We don't want to log the activity of background workers.
	 */
	if (MyProc->isBackgroundWorker)
		return false;
#endif

	/* Get the user name */
#if PG_VERSION_NUM >= 90500
	username = GetUserNameFromId(GetUserId(), false);
#else
	username = GetUserNameFromId(GetUserId());
#endif

	/* Get the database name */
	dbname = get_database_name(MyDatabaseId);

	if (MyProcPort)
		appname = application_name;

#if PG_VERSION_NUM < 90602
	/*
	 * If there are no username and dbname set, it's a background worker
	 * and we don't want to log that kind of activity
	 */
	if (!username && !dbname && !appname)
		return false;
#endif

	/*
	 * Default behavior
	 * log only superuser queries
	 */

	if ((log_db == NULL) && (log_db_blacklist == NULL) &&
	    (log_user == NULL) && (log_user_blacklist == NULL) &&
	    (log_addr == NULL) && (log_app_blacklist == NULL) &&
	    (log_app == NULL) && (log_addr_blacklist == NULL) &&
	    (log_query == NULL) &&(log_query_blacklist == NULL) &&
	    (log_query_id == NULL) &&(log_query_id_blacklist == NULL) &&
	    superuser())
		return true;

	/*
	 * New behaviour if superuser and log_superuser are true, then log
	 * if log_db, log_db_blacklist, log_user, log_user_blacklist, log_addr,
	 * log_addr_blacklist, log_app or log_app_blacklist is set, then log if
	 * regexp matches
	 */

	/* Check superuser */
	if (log_superusers && superuser())
 	{
 		if (match_all == false)
 			return true;
 		else
 			ret = true;
 	}

#if PG_VERSION_NUM >= 140000
	/* Immediately check the queryid blacklist */
	if (log_query_id_blacklist != NULL) {

		rc = pgluq_checkBLitem(	query_id,
			log_query_id_blacklist,
			&query_id_bl_regexv);

		if (!rc)
			// we didn't pass the query_id blacklist
			return false;
	}
#endif

	/* Check the user name */
	if (log_user != NULL || log_user_blacklist != NULL) {
		rc = pgluq_checkitem(	username,
					log_user, &usr_regexv,
					log_user_blacklist, &usr_bl_regexv);
		if (match_all) {
			if (rc)
				ret = true;
			else
				return false;
		} else {
			if (rc)
				return true;
		}
	}

	/* Check the database name */
	if (log_db != NULL || log_db_blacklist != NULL) {
		rc =pgluq_checkitem(	dbname,
					log_db, &db_regexv,
					log_db_blacklist, &db_bl_regexv);
		if (match_all) {
			if (rc)
				ret = true;
			else
				return false;
		} else {
			if (rc)
				return true;
		}
	}

	/* Check the application name */
	if (log_app != NULL || log_app_blacklist != NULL) {
		rc = pgluq_checkitem(	appname,
					log_app, &app_regexv,
					log_app_blacklist, &app_bl_regexv);
		if (match_all) {
			if (rc)
				ret = true;
			else
				return false;
		} else {
			if (rc)
				return true;
		}
	}

	/* Check the inet address */
	if ((log_addr != NULL || log_addr_blacklist != NULL) && MyProcPort)
	{
		addr = MyProcPort->remote_host;
		rc = pgluq_checkitem(	addr,
					log_addr, &addr_regexv,
					log_addr_blacklist, &addr_bl_regexv);
		if (match_all) {
			if (rc)
				ret = true;
			else
				return false;
		} else {
			if (rc)
				return true;
		}
	}
	
#if PG_VERSION_NUM >= 140000
	/* Check the queryid */
	if (log_query_id != NULL ) {
		rc = pgluq_checkWLitem(	query_id,
			  log_query_id, &query_id_regexv);

		if (match_all) {
			if (rc)
				ret = true;
			else
				return false;
		} else {
			if (rc)
				return true;
		}
	}
#endif

	/* Didn't find any interesting condition */
	return ret;
}


/*
 * Log statement according to the user that launched the statement.
 */
static void
pgluq_log(const char *query)
{
	char *tmp_log_query = NULL;

	Assert(query != NULL);

	/* Filter querries according to the white and black list*/
	if (log_query != NULL || log_query_blacklist != NULL) {
		if ( ! pgluq_checkitem(	query,
					log_query, &query_regexv,
					log_query_blacklist, &query_bl_regexv))
			return;
	}

	tmp_log_query = log_prefix(query);
	if (tmp_log_query != NULL)
	{
		/*
		 * Write a message line to syslog or elog
		 * depending on the fact that we opened syslog at the beginning
		 */
		if (openlog_done)
			write_syslog(syslog_level, tmp_log_query);
		else
			ereport(log_level, (errmsg("%s", tmp_log_query), errhidestmt(true)));

		/* Free the string */
		pfree(tmp_log_query);
	}
}

/*
 * Format tag info for log lines; append to the provided buffer.
 */
static char *
log_prefix(const char *query)
{
	int		i;
	int		format_len;
	char	*tmp_log_query = NULL;
	char	pid[10];
	char    duration_msg[60];

	/* Log duration if available */
	if (enable_log_duration) {
		long            secs;
		int             usecs;
		int             msecs;

		TimestampDifference(GetCurrentStatementStartTimestamp(), GetCurrentTimestamp(), &secs, &usecs);
		msecs = usecs / 1000;
		snprintf(duration_msg, 60, "duration: %ld.%03d ms  statement: ",secs * 1000 + msecs, usecs % 1000);
	}
	else
		strcpy(duration_msg, "statement: ");

	/* Allocate the new log string */
	tmp_log_query = palloc(strlen(log_label) + strlen(duration_msg) + strlen(query) + 4096);
	if (tmp_log_query == NULL)
		return NULL;

	/* not sure why this is needed */
	tmp_log_query[0] = '\0';

	/* Parse the log_label string */
	format_len = strlen(log_label);
	for (i = 0; i < format_len; i++)
	{
		if (log_label[i] != '%')
		{
			/* literal char, just copy */
			strncat(tmp_log_query, log_label+i, 1);
			continue;
		}
		/* go to char after '%' */
		i++;

		if (i >= format_len)
			break;				/* format error - ignore it */

		/* process the option */
		switch (log_label[i])
		{
#if PG_VERSION_NUM >= 90000
			case 'a':
				if (MyProcPort)
				{
					const char *appname = application_name;

					if (appname == NULL || *appname == '\0')
						appname = _("[unknown]");
                    strncat(tmp_log_query, appname, strlen(tmp_log_query));
				}
				break;
#endif
			case 'u':
				if (MyProcPort)
				{
#if PG_VERSION_NUM >= 90500
					const char *username = GetUserNameFromId(GetUserId(), false);
#else
					const char *username = GetUserNameFromId(GetUserId());
#endif

					if (username == NULL || *username == '\0')
						username = _("[unknown]");
                    strncat(tmp_log_query, username, strlen(tmp_log_query));
				}
				break;
			case 'd':
				if (MyProcPort)
				{
					const char *dbname = get_database_name(MyDatabaseId);

					if (dbname == NULL || *dbname == '\0')
						dbname = _("[unknown]");
                    strncat(tmp_log_query, dbname, strlen(tmp_log_query));
				}
				break;
			case 'p':
				sprintf(pid, "%d", MyProcPid);
                strcat(tmp_log_query, pid);
				break;
			case '%':
				strcat(tmp_log_query, "%");
				break;
			default:
				/* format error - ignore it */
				break;
		}
	}

	/* Check if there's a space at the end, and add one if there isn't */
	if (strlen(tmp_log_query) > 0 && strcmp(&tmp_log_query[strlen(tmp_log_query)-1], " "))
		strcat(tmp_log_query, " ");

	/* add duration information if available */
	if (strlen(duration_msg) > 0)
		strcat(tmp_log_query, duration_msg);

	/* Add the query at the end */
	strcat(tmp_log_query, query);

	/* Return the whole string */
	return tmp_log_query;
}

/*
 * Write a message line to syslog
 */
static void
write_syslog(int level, char *line)
{
	static unsigned long seq = 0;
	int len;
	const char *nlpos;

	/*
	 * We add a sequence number to each log message to suppress "same"
	 * messages.
	 */
	seq++;

	/*
	 * Our problem here is that many syslog implementations don't handle long
	 * messages in an acceptable manner. While this function doesn't help that
	 * fact, it does work around by splitting up messages into smaller pieces.
	 *
	 * We divide into multiple syslog() calls if message is too long or if the
	 * message contains embedded newline(s).
	 */
	len = strlen(line);
	nlpos = strchr(line, '\n');
	if (len > PG_SYSLOG_LIMIT || nlpos != NULL)
	{
		int chunk_nr = 0;
		while (len > 0)
		{
			char buf[PG_SYSLOG_LIMIT + 1];
			int  buflen;
			int  i;

			/* if we start at a newline, move ahead one char */
			if (line[0] == '\n')
			{
				 line++;
				 len--;
				 /* we need to recompute the next newline's position, too */
				 nlpos = strchr(line, '\n');
				 continue;
			}

			/* copy one line, or as much as will fit, to buf */
			if (nlpos != NULL)
				buflen = nlpos - line;
			else
				buflen = len;
			buflen = Min(buflen, PG_SYSLOG_LIMIT);
			memcpy(buf, line, buflen);
			buf[buflen] = '\0';

			/* trim to multibyte letter boundary */
			buflen = pg_mbcliplen(buf, buflen, buflen);
			if (buflen <= 0)
				return;
			buf[buflen] = '\0';

			/* already word boundary? */
			if (line[buflen] != '\0' &&
				!isspace((unsigned char) line[buflen]))
			{
				/* try to divide at word boundary */
				i = buflen - 1;
				while (i > 0 && !isspace((unsigned char) buf[i]))
					i--;

				/* else couldn't divide word boundary */
				if (i > 0)
				{
					buflen = i;
					buf[i] = '\0';
				}
			}

			chunk_nr++;

			syslog(level, "[%lu-%d] %s", seq, chunk_nr, buf);
			line += buflen;
			len -= buflen;
		}
	}
	else
	{
		/* message short enough */
		syslog(level, "[%lu] %s", seq, line);
	}
}

/*
 * Check if we have reached the time interval defined (time_switchoff)
 * Default value is 300 seconds (if not set or out of range)
 * Valid range is from 30 to 3600 seconds
 */
static bool check_time_switch(void)
{
	bool time2check = false;
	time_t cur_time;
	int save_errno;

	if (time(&cur_time) == -1)
	{
		save_errno = errno;
		elog(log_level,
			"Unable to get current time: %s (%d).",
#if PG_VERSION_NUM >= 120000
			pg_strerror(save_errno),
#else
			strerror(save_errno),
#endif
			save_errno);
    }

	if ((int)(cur_time-ref_time) > time_switchoff)
	{
		time2check = true;
		ref_time = cur_time;
	}

	return time2check;
}

/*
 * Function to determine if pg_log_userqueries needs to be de/re-activated on the fly.
 * Allows to switch off/on the function without restarting PostgreSQL.
 * Check if file_switchoff string has been set and exists.
 * This check is done at server startup and every time_switchoff interval.
 * This means that if the file is created, each new connection will be affected.
 * Others will have to wait the time interval change for detection.
 */
static bool check_switchoff(void)
{
	struct stat stat_file_switchoff;
	int r_stat;
	int save_errno;

	if (file_switchoff == NULL)
		return false;

	if (check_time_switch())
	{
		if ((r_stat = stat(file_switchoff, &stat_file_switchoff)) < 0 )
		{
			if (errno != 2)
			{
				save_errno = errno;
				elog(WARNING,
					"Unable to get switchoff file stats (%s): %s (%d).",
					file_switchoff,
#if PG_VERSION_NUM >= 120000
				  pg_strerror(save_errno),
#else
			    strerror(errno),
#endif
				  save_errno);
			}
			if (switch_off) /* write once */
				elog(NOTICE, "Switch off file unfound. Switching on pg_log_userqueries.");
			switch_off = false;
		}
		else /* Permissions checking */
		{
			if (stat_file_switchoff.st_uid != 0 ||			/* owner root */
				stat_file_switchoff.st_gid != 0 ||			/* group root */
				!S_ISREG(stat_file_switchoff.st_mode) ||	/* regular file */
				(stat_file_switchoff.st_mode & (S_IXOTH|S_IWOTH|S_IROTH|S_IXGRP|S_IWGRP|S_IRGRP)))
			{
				/* No permissions for group and others: there is a security risk */
				elog(WARNING,
					"File %s found with incorrect owner or permission.\n"
					"It should belong to root.root, be regular, and have no permission for group/others.",
					file_switchoff
					);
				switch_off = false;
			}
			else
			{
				if (!switch_off) /* write once */
					elog(NOTICE, "Switch off file found. Switching off pg_log_userqueries.");
				switch_off = true;
			}
		}
	}

	return switch_off;
}
