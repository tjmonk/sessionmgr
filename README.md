# sessionmgr
Session Manager

## Overview

The session manager is a service which manages external access
to the system.  It creates a unique session identifier for each session
and ties that session to a user identifier to manage access credentials.

The session manager is split into 3 parts:

- the session management service itself
- a shared object library which provides a session management API
- a session utility which is typically just used for testing

The session manager is part of The Gateway Project and is designed to
work with the variable server for its configuration and status reporting.

## Operation

### Session Creation

A new session is created by invoking the SESSIONMGR_NewSession API function.
A username and password are provided along with a reference identifier.
The reference identifier uniquely identifies the requesting client and
is usually a client ip address, or MAC address or some other reference.
Logins from the same source (same reference) do not create a new login,
but will reference the previous login from the same username and reference.

The username/password combination is validated against the system password
database using the standard POSIX APIs: getpwnam, crypt, and getspnam.
The crypt algorithm is used to encrypt the supplied password and compare
that against the system's similiarly encrypted password.

If the passwords match, a new session is created or an old session is
retrieved if one already existed for that user/reference combination.

For new sessions, a random session identifier is created and returned
to the caller.  This session identifier is used to subsequently reference
the session and the username, password, and client reference are no
longer used.

### Session Validation

Subsequent interactions from the client can be authenticated with the
session identifier.  The SESSIONMGR_Validate function passes a user
supplied session identifier.  It returns the userid associated with
the authenticated user if the session identifier was found among the
valid session list.  Thus the session manager provides both authorization
and authentication, associating different priviledges to each session
depending on the priviledge of the authenticated user.

The SESSIONMGR_Authenticate function performs session validation
but also sets the effective user identifier of the calling process
to the user identifier associated with the session identifier.

### Session Termination

Sessions can be terminated using the SESSIONMGR_EndSession function, again
just by passing in the session identifier of a valid active session.
Once a session is terminated, it is deleted from the active session list
and can no longer be validated.

### Session Timeouts

Sessions can have a specified timeout - a number of seconds that the session
can be valid.  The session manager will periodically update sessions
that have a timeout and automatically terminate sessions which exceed the
timeout duration.

### Session Auto Extend

Sessions can be set to auto-extend every time the SESSION_Valdiate function
is invoked for that session.  In this case, the session timeout is reset to
its initial value for any successful validation of the session.  A
session configured in this way can be kept alive indefinitely, but will
auto terminate once the client stops interacting with the session.

## Session Manager Configuration

The behavior of the session manager can be configured via varserver variables.
The variables are optional, and if they are not present, the default behaviors
will be used instead.

| | | | |
|---|---|---|---|
| Variable Name | Variable Description | Usage | Default Behavior |
| /sys/session/info | Used to query a list of active sessions as a JSON object | | session info is unavailable |
| /sys/session/enable | When set to 0 disable all current and future sessions |  0=disable 1=enable | session manager is enabled |
| /sys/session/timeout | Session timeout for all future sessions | Timeout is specified in seconnds.  A session timeout of 0 will disable all automatic session termination, and sessions will persist forever unless explicitly terminated | Session timeout is 300 seconds
| /sys/session/autoextend | Allow sessions to auto-extend whenever client activity is detected | 0=disable autoextend 1=enable autoextend.  | Sessions do not auto-extend |

Variables can be changed at run-time and the changes will have immediate
impact on the behavior of session manager.

## Building the Session Manager

A build script is provided which will invoke CMake to build the session manager.
The varserver component is a pre-requisite and must be built/installed prior
to building the session manager.

## Running the session manager

### Create the session manager configuration variables if required

```bash
mkvar -t uint16 -n /sys/session/info
mkvar -t uint16 -n /sys/session/enable -v 1
mkvar -t uint16 -n /sys/session/timeout -v 500
mkvar -t uint16 -n /sys/session/autoextend -v 1
```

### Start the session manager

```bash
sessionmgr &
```

###  Run the session test script

```
./test/sessiontest.sh
```

The session test script takes the following actions

- create a new user called bob
- create two groups: reader, and writer
- adds the user bob to the reader and writer groups
- creates a new random password for bob
- logs bob in
- lists the current active sessions
- validates bob's session using his session identifier
- validates bob's session and dumps verbose output
- tries to validate an invalid session
- terminates bob's session
- confirms bob's session is gone
- lists the current active sessions again
- deletes user bob
- delets the reader and writer groups

The output of a successful test should be as follows:

```bash
Creating Session: PASSED
/sys/session/info=[{ "user": "bob", "userid": "1000","reference": "session_tester","session": "9ShvbiEe","remaining": 300 }]
Checking session valid: PASSED
user = bob
uid = 1000
gid = 1000
1000 (bob)
1004 (reader)
1005 (writer)
Checking invalid session: PASSED
Terminating session: PASSED
Checking bob's session is gone: PASSED
/sys/session/info=[]
```

## Using the session utility

The session utility can be used to test and execute the session manager
API.   The sessiontest.sh script uses the session utility to perform
its tests.

The session utility supports the following command line options:

| Option | Description |
|---|---|
| -v | enable verbose mode |
| -u user | specify the login user name |
| -p password | specify the login user password |
| -r reference | specify the client reference |
| -m mode | specify the operating mode: login, logout, or validate |
| -s session | specify the session identifier |

The -u, -p, and -r options are only valid when the operating mode is 'login'
The -s options is only valid when the operating mode is 'logout' or 'validate'

### Creating a new session with the session utility

To create a new session use -m login, and -u and -p to specify the user
name and password.  The -r reference is optional and the reference will
be set to "session_tester" if no reference is specified.
If -v is specified the session id will be output to the standard output stream.

For example to create a new session and capture the session identifier,
the following command could be used.  This example assumes that user
"bob" exists and his password is "bobspassword".

```bash
token=`session -m login -u bob -p bobspassword -v`
```

### Validating a session

The session can be validated using -m validate and -s sessionid.

For example:

```bash
session -m validate -s $token
```

If the session is valid the return value of the session command
will be zero, If the session is invalid, the return value will
be non-zero.

### Terminating a session

The session can be terminated using the -m logout and -s sessionid.

For example:

```bash
session -m logout -s $token
```
