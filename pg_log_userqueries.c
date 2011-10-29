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
	 * allow the pg_stat_statements functions to be created even when the
	 * module isn't active.  The functions must protect themselves against
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
#endif

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
	Assert(query != NULL);

    if (superuser())
        elog(log_level, "%s %s: %s", log_label, GetUserNameFromId(GetUserId()), query);
}

