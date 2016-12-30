/*
 * Console back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

typedef struct console_backend_data {
	HANDLE shell_in_w;
	HANDLE shell_out_r;
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
    if (console->shell_in_w != INVALID_HANDLE_VALUE) {
	CloseHandle(console->shell_in_w);
	console->shell_in_w = INVALID_HANDLE_VALUE;
    }
	if (console->shell_out_r != INVALID_HANDLE_VALUE) {
		CloseHandle(console->shell_out_r);
		console->shell_out_r = INVALID_HANDLE_VALUE;
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
    HANDLE shell_in_r;
	HANDLE shell_in_w;
	HANDLE shell_out_r;
	HANDLE shell_out_w;
	HANDLE shell_err_w;
	const char *err;
    char *shell;
	SECURITY_ATTRIBUTES saAttr;
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&shell_out_r, &shell_out_w, &saAttr, 0))
		return "Unable to open output pipe";
	if (!SetHandleInformation(shell_out_r, HANDLE_FLAG_INHERIT, 0))
		return "Setting out handle inheritance failed";
	if (!CreatePipe(&shell_in_r, &shell_in_w, &saAttr, 0))
		return "Unable to open input pipe";
	if (!SetHandleInformation(shell_in_w, HANDLE_FLAG_INHERIT, 0))
		return "Setting in handle inheritance failed";

	if (!DuplicateHandle(GetCurrentProcess(), shell_out_w, GetCurrentProcess(), &shell_err_w, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		return "Unable to create stderr output handle";
	}

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = shell_err_w;
	siStartInfo.hStdOutput = shell_out_w;
	siStartInfo.hStdInput = shell_in_r;
	siStartInfo.dwFlags = STARTF_USESTDHANDLES;

	console = snew(struct console_backend_data);
	console->shell_in_w = shell_in_w;
	console->shell_out_r = shell_out_r;
	console->out = console->in = NULL;
	console->bufsize = 0;
	*backend_handle = console;

	console->frontend = frontend_handle;

	shell = conf_get_str(conf, CONF_shell);
	{
		char *msg = dupprintf("Starting shell %s", shell);
		logevent(console->frontend, msg);
	}

	if (!CreateProcess(NULL, shell, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &siStartInfo, &piProcInfo)) {
		return "Unable to create shell process";
	}

    console->out = handle_output_new(shell_in_w, console_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED);
    console->in = handle_input_new(shell_out_r, console_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF |
				  HANDLE_FLAG_UNITBUFFER);

    *realhost = dupstr(shell);

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
	/* do nothing */
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
    if (console->shell_in_w != INVALID_HANDLE_VALUE)
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
