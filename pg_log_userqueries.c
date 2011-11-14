/*-------------------------------------------------------------------------
 *
 * pg_log_userqueries.c
 *		Log statement according to the user.
 *
 *
 * Copyright (c) 2011, Guillaume Lelarge (Dalibo),
 * guillaume.lelarge@dalibo.com
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <unistd.h>

#include "funcapi.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include <regex.h>

PG_MODULE_MAGIC;


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


static int    log_level = NOTICE;
static char * log_label = NULL;
static char * log_user = NULL;
static char * log_db = NULL;
static int regex_flags = REG_NOSUB;
static regex_t usr_regexv;
static regex_t db_regexv;

/* Saved hook values in case of unload */
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
#if PG_VERSION_NUM >= 90000
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
#endif


/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

static void pgluq_ExecutorEnd(QueryDesc *queryDesc);
#if PG_VERSION_NUM >= 90000
static void pgluq_ProcessUtility(Node *parsetree,
			  const char *queryString, ParamListInfo params, bool isTopLevel,
					DestReceiver *dest, char *completionTag);
#endif
static void pgluq_log(const char *query);

extern char *get_database_name(Oid dbid);

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
    *        * Define (or redefine) custom GUC variables.
    */
#if PG_VERSION_NUM >= 90100
   DefineCustomStringVariable( "pg_log_userqueries.log_label",
                               "Label in front of the user query.",
                               NULL,
                               &log_label,
                               "pg_log_userqueries",
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL,
                               NULL );
   DefineCustomEnumVariable( "pg_log_userqueries.log_level",
                               "Selects level of log (same options than log_min_messages.",
                               NULL,
                               &log_level,
                               log_level,
                               server_message_level_options,
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL,
                               NULL);
   DefineCustomStringVariable( "pg_log_userqueries.log_user",
                               "Log statement according to the given user.",
                               NULL,
                               &log_user,
                               NULL,
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL,
                               NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_db",
                               "Log statement according to the given database.",
                               NULL,
                               &log_db,
                               NULL,
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL,
                               NULL );
#else
   DefineCustomStringVariable( "pg_log_userqueries.log_label",
                               "Label in front of the user query.",
                               NULL,
                               &log_label,
                               "pg_log_userqueries",
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL );
   DefineCustomEnumVariable( "pg_log_userqueries.log_level",
                               "Selects level of log (same options than log_min_messages.",
                               NULL,
                               &log_level,
                               log_level,
                               server_message_level_options,
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL);
   DefineCustomStringVariable( "pg_log_userqueries.log_user",
                               "Log statement according to the given user.",
                               NULL,
                               &log_user,
                               NULL,
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL );
   DefineCustomStringVariable( "pg_log_userqueries.log_db",
                               "Log statement according to the given database.",
                               NULL,
                               &log_db,
                               NULL,
                               PGC_POSTMASTER,
                               0,
                               NULL,
                               NULL );
#endif

	/* Add support to extended regex search */
	regex_flags |= REG_EXTENDED;
	/* compile rexgex for user and db name */
	if (log_user != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_user) + 5));
		sprintf(tmp, "^(%s)$", log_user);
		if (regcomp(&usr_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid user pattern %s", tmp)));
		}
		pfree(tmp);
	}
	if (log_db != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_db) + 5));
		sprintf(tmp, "^(%s)$", log_db);
		if (regcomp(&db_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid database pattern %s", tmp)));
		}
		pfree(tmp);
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
	/* Uninstall hooks. */
	ExecutorEnd_hook = prev_ExecutorEnd;
#if PG_VERSION_NUM >= 90000
	ProcessUtility_hook = prev_ProcessUtility;
#endif
}

/*
 * ExecutorEnd hook: store results if needed
 */
static void
pgluq_ExecutorEnd(QueryDesc *queryDesc)
{
    pgluq_log(queryDesc->sourceText);

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

#if PG_VERSION_NUM >= 90000
/*
 * ProcessUtility hook
 */
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

		pgluq_log(queryString);
}
#endif

/*
 * Log statement according to the user that launched the statement.
 */
static void
pgluq_log(const char *query)
{
	/* database variables */
	bool dbmatch = false;
	char *dbname  = NULL;
	/* user variables */
	bool usermatch = false;
	char *username = NULL;

	Assert(query != NULL);

	/* Default behavior: log only superuser queries */
	if ((log_db == NULL) && (log_user == NULL) && superuser())
	{
		username = GetUserNameFromId(GetUserId());
		elog(log_level, "%s (superuser=%s): %s", log_label, username, query);
	}
    /* 
     * New behaviour
     * if log_db or log_user is set, then log if regexp matches
     */
	else
	{
		/* Get the user name */
		username = GetUserNameFromId(GetUserId());

		/* Get the database name (unknown if we don't have one) */
		dbname = get_database_name(MyDatabaseId);
		if (dbname == NULL || *dbname == '\0')
			dbname = _("unknown");

		/* Check if we match the regexp */
		dbmatch = (log_db != NULL) && (regexec(&db_regexv, dbname, 0, 0, 0) == 0);
		usermatch = (log_user != NULL) && (regexec(&usr_regexv, username, 0, 0, 0) == 0);

		/* Log them if appropriate */
		if (dbmatch && usermatch)
			elog(log_level, "%s (database=%s,user=%s): %s", log_label, dbname, username, query);
		else if (dbmatch)
			elog(log_level, "%s (database=%s): %s", log_label, dbname, query);
		else if (usermatch)
			elog(log_level, "%s (user=%s): %s", log_label, username, query);
	}
}

