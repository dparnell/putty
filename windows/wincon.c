/*
 * Console back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

typedef struct console_backend_data {
    HANDLE port;
    struct handle *out, *in;
    void *frontend;
    int bufsize;
} *Console;

static void console_terminate(Console console)
{
    if (console->out) {
	handle_free(console->out);
	console->out = NULL;
    }
    if (console->in) {
	handle_free(console->in);
	console->in = NULL;
    }
    if (console->port != INVALID_HANDLE_VALUE) {
	CloseHandle(console->port);
	console->port = INVALID_HANDLE_VALUE;
    }
}

static int console_gotdata(struct handle *h, void *data, int len)
{
    Console console = (Console)handle_get_privdata(h);
    if (len <= 0) {
	const char *error_msg;

	/*
	 * Currently, len==0 should never happen because we're
	 * ignoring EOFs. However, it seems not totally impossible
	 * that this same back end might be usable to talk to named
	 * pipes or some other non-console device, in which case EOF
	 * may become meaningful here.
	 */
	if (len == 0)
	    error_msg = "End of file reading from console device";
	else
	    error_msg = "Error reading from console device";

	console_terminate(console);

	notify_remote_exit(console->frontend);

	logevent(console->frontend, error_msg);

	connection_fatal(console->frontend, "%s", error_msg);

	return 0;		       /* placate optimiser */
    } else {
	return from_backend(console->frontend, 0, data, len);
    }
}

static void console_sentdata(struct handle *h, int new_backlog)
{
    Console console = (Console)handle_get_privdata(h);
    if (new_backlog < 0) {
	const char *error_msg = "Error writing to console device";

	console_terminate(console);

	notify_remote_exit(console->frontend);

	logevent(console->frontend, error_msg);

	connection_fatal(console->frontend, "%s", error_msg);
    } else {
	console->bufsize = new_backlog;
    }
}

static const char *console_configure(Console console, HANDLE serport, Conf *conf)
{
	/* Do nothing for now */

    return NULL;
}

/*
 * Called to set up the console connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *console_init(void *frontend_handle, void **backend_handle,
			       Conf *conf, const char *host, int port,
			       char **realhost, int nodelay, int keepalive)
{
    Console console;
    HANDLE serport;
    const char *err;
    char *serline;

    console = snew(struct console_backend_data);
    console->port = INVALID_HANDLE_VALUE;
    console->out = console->in = NULL;
    console->bufsize = 0;
    *backend_handle = console;

    console->frontend = frontend_handle;

    serline = conf_get_str(conf, CONF_serline);
    {
	char *msg = dupprintf("Opening console device %s", serline);
	logevent(console->frontend, msg);
    }

    {
	/*
	 * Munge the string supplied by the user into a Windows filename.
	 *
	 * Windows supports opening a few "legacy" devices (including
	 * COM1-9) by specifying their names verbatim as a filename to
	 * open. (Thus, no files can ever have these names. See
	 * <http://msdn2.microsoft.com/en-us/library/aa365247.aspx>
	 * ("Naming a File") for the complete list of reserved names.)
	 *
	 * However, this doesn't let you get at devices COM10 and above.
	 * For that, you need to specify a filename like "\\.\COM10".
	 * This is also necessary for special console and console-like
	 * devices such as \\.\WCEUSBSH001. It also works for the "legacy"
	 * names, so you can do \\.\COM1 (verified as far back as Win95).
	 * See <http://msdn2.microsoft.com/en-us/library/aa363858.aspx>
	 * (CreateFile() docs).
	 *
	 * So, we believe that prepending "\\.\" should always be the
	 * Right Thing. However, just in case someone finds something to
	 * talk to that doesn't exist under there, if the console line
	 * contains a backslash, we use it verbatim. (This also lets
	 * existing configurations using \\.\ continue working.)
	 */
	char *serfilename =
	    dupprintf("%s%s", strchr(serline, '\\') ? "" : "\\\\.\\", serline);
	serport = CreateFile(serfilename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
			     OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	sfree(serfilename);
    }

    if (serport == INVALID_HANDLE_VALUE)
	return "Unable to open console port";

    err = console_configure(console, serport, conf);
    if (err)
	return err;

    console->port = serport;
    console->out = handle_output_new(serport, console_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED);
    console->in = handle_input_new(serport, console_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF |
				  HANDLE_FLAG_UNITBUFFER);

    *realhost = dupstr(serline);

    /*
     * Specials are always available.
     */
    update_specials_menu(console->frontend);

    return NULL;
}

static void console_free(void *handle)
{
    Console console = (Console) handle;

    console_terminate(console);
    expire_timer_context(console);
    sfree(console);
}

static void console_reconfig(void *handle, Conf *conf)
{
    Console console = (Console) handle;
    const char *err;

    err = console_configure(console, console->port, conf);

    /*
     * FIXME: what should we do if err returns something?
     */
}

/*
 * Called to send data down the console connection.
 */
static int console_send(void *handle, const char *buf, int len)
{
    Console console = (Console) handle;

    if (console->out == NULL)
	return 0;

    console->bufsize = handle_write(console->out, buf, len);
    return console->bufsize;
}

/*
 * Called to query the current sendability status.
 */
static int console_sendbuffer(void *handle)
{
    Console console = (Console) handle;
    return console->bufsize;
}

/*
 * Called to set the size of the window
 */
static void console_size(void *handle, int width, int height)
{
    /* Do nothing! */
    return;
}

static void serbreak_timer(void *ctx, unsigned long now)
{
	// do nothing
}

/*
 * Send console special codes.
 */
static void console_special(void *handle, Telnet_Special code)
{
	// do nothing
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
static const struct telnet_special *console_get_specials(void *handle)
{
    static const struct telnet_special specials[] = {
	{NULL, TS_EXITMENU}
    };
    return specials;
}

static int console_connected(void *handle)
{
    return 1;			       /* always connected */
}

static int console_sendok(void *handle)
{
    return 1;
}

static void console_unthrottle(void *handle, int backlog)
{
    Console console = (Console) handle;
    if (console->in)
	handle_unthrottle(console->in, backlog);
}

static int console_ldisc(void *handle, int option)
{
    /*
     * Local editing and local echo are off by default.
     */
    return 0;
}

static void console_provide_ldisc(void *handle, void *ldisc)
{
    /* This is a stub. */
}

static void console_provide_logctx(void *handle, void *logctx)
{
    /* This is a stub. */
}

static int console_exitcode(void *handle)
{
    Console console = (Console) handle;
    if (console->port != INVALID_HANDLE_VALUE)
        return -1;                     /* still connected */
    else
        /* Exit codes are a meaningless concept with console ports */
        return INT_MAX;
}

/*
 * cfg_info for console does nothing at all.
 */
static int console_cfg_info(void *handle)
{
    return 0;
}

Backend console_backend = {
    console_init,
    console_free,
    console_reconfig,
    console_send,
    console_sendbuffer,
    console_size,
    console_special,
    console_get_specials,
    console_connected,
    console_exitcode,
    console_sendok,
    console_ldisc,
    console_provide_ldisc,
    console_provide_logctx,
    console_unthrottle,
    console_cfg_info,
    NULL /* test_for_upstream */,
    "console",
    PROT_CONSOLE,
    0
};
