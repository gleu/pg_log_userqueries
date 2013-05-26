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
#include <regex.h>
#include <syslog.h>

#include "funcapi.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include "libpq/libpq-be.h"

PG_MODULE_MAGIC;

#ifndef PG_SYSLOG_LIMIT
#define PG_SYSLOG_LIMIT 1024
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


static int     log_level = NOTICE;
static char *  log_label = NULL;
static char *  log_user = NULL;
static char *  log_db = NULL;
static char *  log_addr = NULL;
static int     regex_flags = REG_NOSUB;
static regex_t usr_regexv;
static regex_t db_regexv;
static regex_t addr_regexv;
static bool    openlog_done = false;
static char *  syslog_ident = NULL;
static int     log_destination = 1; /* aka stderr */
static int     syslog_facility = LOG_LOCAL0;
static int     syslog_level = LOG_NOTICE;

/* Saved hook values in case of unload */
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
#if PG_VERSION_NUM >= 90000
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
#endif


/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

static void pgluq_ExecutorEnd(QueryDesc *queryDesc);
#if PG_VERSION_NUM >= 90300
static void pgluq_ProcessUtility(Node *parsetree,
			  const char *queryString, ProcessUtilityContext context, ParamListInfo params,
					DestReceiver *dest, char *completionTag);
#elif PG_VERSION_NUM >= 90000
static void pgluq_ProcessUtility(Node *parsetree,
			  const char *queryString, ParamListInfo params, bool isTopLevel,
					DestReceiver *dest, char *completionTag);
#endif
static bool pgluq_check_log(void);
static void pgluq_log(const char *query);
static void write_syslog(int level, char *line);
static char *log_prefix(const char *query);

extern char *get_database_name(Oid dbid);
extern int pg_mbcliplen(const char *mbstr, int len, int limit);

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
				"Selects level of log (same options than log_min_messages.",
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

	/* Add support to extended regex search */
	regex_flags |= REG_EXTENDED;
	/* Compile rexgex for user name */
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
	/* Compile rexgex for db name */
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
	/* Compile rexgex for inet addr */
	if (log_addr != NULL)
	{
		char *tmp;
		tmp = palloc(sizeof(char) * (strlen(log_addr) + 5));
		sprintf(tmp, "^(%s)$", log_addr);
		if (regcomp(&addr_regexv, tmp, regex_flags) != 0)
		{
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("pg_log_userqueries: invalid address pattern %s", tmp)));
		}
		pfree(tmp);
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
}

/*
 * ExecutorEnd hook: store results if needed
 */
static void
pgluq_ExecutorEnd(QueryDesc *queryDesc)
{
    if (pgluq_check_log())
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
#if PG_VERSION_NUM >= 90300
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
 * Check if we should log
 */
static bool pgluq_check_log()
{
	/* object's name */
	char *dbname  = NULL;
	char *username = NULL;
	char *addr = NULL;

	/*
	 * Default behavior
	 * log only superuser queries
	 */

	if ((log_db == NULL) && (log_user == NULL) && (log_addr == NULL) && superuser())
		return true;

	/* 
	 * New behaviour
	 * if log_db, log_user, or log_addr is set, then log if regexp matches
	 */

	/* Check the user name */
	username = GetUserNameFromId(GetUserId());
	if ((log_user != NULL) && (regexec(&usr_regexv, username, 0, 0, 0) == 0))
		return true;

	/* Check the database name */
	dbname = get_database_name(MyDatabaseId);
	if (dbname == NULL || *dbname == '\0')
		dbname = _("unknown");
	if ((log_db != NULL) && (regexec(&db_regexv, dbname, 0, 0, 0) == 0))
		return true;

    /* Check the inet address */
    if (MyProcPort)
    {
        addr = MyProcPort->remote_host;
        if ((log_addr != NULL) && regexec(&addr_regexv, addr , 0, 0, 0) == 0)
            return true;
    }

	/* Didn't find any interesting condition */
	return false;
}

/*
 * Log statement according to the user that launched the statement.
 */
static void
pgluq_log(const char *query)
{
	char *tmp_log_query = NULL;

	Assert(query != NULL);

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
			elog(log_level, "%s", tmp_log_query);

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

	/* Allocate the new log string */
    tmp_log_query = palloc(strlen(log_label) + strlen(query) + 4096);
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
            sprintf(tmp_log_query, "%s%c", tmp_log_query, log_label[i]);
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
                    strcat(tmp_log_query, appname);
				}
				break;
#endif
			case 'u':
				if (MyProcPort)
				{
					const char *username = GetUserNameFromId(GetUserId());

					if (username == NULL || *username == '\0')
						username = _("[unknown]");
                    strcat(tmp_log_query, username);
				}
				break;
			case 'd':
				if (MyProcPort)
				{
					const char *dbname = get_database_name(MyDatabaseId);

					if (dbname == NULL || *dbname == '\0')
						dbname = _("[unknown]");
                    strcat(tmp_log_query, dbname);
				}
				break;
			case 'p':
                sprintf(tmp_log_query, "%s%d", tmp_log_query, MyProcPid);
				break;
			case '%':
                sprintf(tmp_log_query, "%s%%", tmp_log_query);
				break;
			default:
				/* format error - ignore it */
				break;
		}
	}

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

