/*==============================================================================
MIT License

Copyright (c) 2023 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup sessionmgr sessionmgr
 * @brief Session Manager
 * @{
 */

/*============================================================================*/
/*!
@file sessionmgr.c

    Session Manager

    The Session Manager manages active user sessions to the system
    via external interfaces such as web services.
    Sessions may be initiated with the correct user credentials.
    Sessions persist for a specific period before they are invalidated

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/random.h>
#include <signal.h>
#include <time.h>
#include <sys/un.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <varserver/varserver.h>
#include <sessionmgr/sessionmgr.h>
#include <tjwt/tjwt.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*! name of variable get get session information */
#ifndef SESSION_INFO_NAME
#define SESSION_INFO_NAME "/sys/session/info"
#endif

/*! name of variable to enable session handling */
#ifndef SESSION_ENABLE_NAME
#define SESSION_ENABLE_NAME "/sys/session/cfg_enable"
#endif

/*! name of variable to enable session handling */
#ifndef SESSION_TIMEOUT_NAME
#define SESSION_TIMEOUT_NAME "/sys/session/cfg_timeout"
#endif

/*! name of variable to enable automatic timeout extension */
#ifndef SESSION_AUTOEXTEND_NAME
#define SESSION_AUTOEXTEND_NAME "/sys/session/cfg_autoextend"
#endif

/*! name of variable to enable sesssion auditing */
#ifndef SESSION_AUDIT_NAME
#define SESSION_AUDIT_NAME "/sys/session/cfg_audit"
#endif

#ifndef SESSION_AUDIENCE_NAME
#define SESSION_AUDIENCE_NAME "/sys/session/cfg_audience"
#endif

#ifndef SESSION_ISSUER_NAME
#define SESSION_ISSUER_NAME  "/sys/session/cfg_issuer"
#endif

#ifndef SESSION_KEYSTORE_NAME
#define SESSION_KEYSTORE_NAME "/sys/session/cfg_keystore"
#endif

#ifndef SESSION_USERLIST_NAME
#define SESSION_USERLIST_NAME "/sys/session/cfg_users"
#endif

/*! timer notification */
#define TIMER_NOTIFICATION SIGRTMIN+5

/*! timer rate */
#define TIMER_S 5

#ifndef DEFAULT_SESSION_TIMEOUT
/*! default session timeout */
#define DEFAULT_SESSION_TIMEOUT 300
#endif

/*==============================================================================
        Private types
==============================================================================*/

/*! session manager client node */
typedef struct sessionMgrClient
{
    /*! file descriptor of the session manager client */
    int fd;

    /*! pointer to the next session manager client */
    struct sessionMgrClient *pNext;
} SessionMgrClient;

/*! The sessionInfo object is used to track the active client sessions */
typedef struct sessionInfo
{
    /*! length of time remaining on the session */
    int timeout;

    /*! session identifier */
    char sessionId[SESSION_ID_LEN+1];

    /*! user name */
    char username[SESSION_MAX_USERNAME_LEN+1];

    /*! client reference */
    char reference[SESSION_MAX_REFERENCE_LEN+1];

    /*! session user information */
    uid_t uid;

    /*! pointer to the next session info object in the list */
    struct sessionInfo *pNext;

} SessionInfo;

/*! The var type combines a variable handle and its object to
    ease configuration management */
typedef struct _vs_var
{
    /* handle to the variable */
    VAR_HANDLE hdl;

    /* variable value  */
    VarObject obj;
} var;

/*! uint16 variable initialization */
typedef struct _init_var16
{
    /*! pointer to the variable to be initialized */
    var *pVar;

    /* value to be initialized */
    uint16_t val;
} InitVar16;

/*! Session Manager state */
typedef struct sessionMgrState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! verbose flag */
    bool verbose;

    /*! show program usage */
    bool usage;

    /*! connection socket to listen on for client connections */
    int sock;

    /*! session information rendered variable */
    var sessionInfo;

    /*! session manager enable variable */
    var sessionEnable;

    /*! session timeout variable */
    var sessionTimeout;

    /*! session autoextend variable */
    var autoExtend;

    /*! audit enable variable */
    var audit;

    /*! token key store */
    var keystore;

    /*! expected token issuer */
    var issuer;

    /*! expected token audience */
    var audience;

    /*! allowed user list */
    var users;

    /*! set of sockets waiting to be read */
    fd_set read_fds;

    /*! max file descriptor in the read_fds list */
    int maxfd;

    /*! variable server file descriptor to receive signals on */
    int varserver_fd;

    /*! list of free session client objects */
    SessionMgrClient *pFreeList;

    /*! list of active session clients */
    SessionMgrClient *pClientList;

    /*! pointer to the session info free list */
    SessionInfo *pFreeSessions;

    /*! pointer to the active sessions */
    SessionInfo *pActiveSessions;

} SessionMgrState;

/*! handle session configuration variables */
typedef struct session_vars
{
    /*! variable name */
    char *pName;

    /*! pointer to the variable */
    var *pVar;

    /*! type of notification */
    NotificationType notifyType;

} SessionVars;

/*==============================================================================
        Private function declarations
==============================================================================*/

static int ProcessOptions( int argC, char *argV[], SessionMgrState *pState );
static void TerminationHandler( int signum, siginfo_t *info, void *ptr );
static void usage( char *cmdname );
static void SetupTerminationHandler( void );
static int SessionMgrInit( SessionMgrState *pState );
static int SetupNotifications( SessionMgrState *pState );
static int NewClient( SessionMgrState *pState, int fd );
static int DeleteClient( SessionMgrState *pState, int fd );
static int UpdateFDSet( SessionMgrState *pState );
static int ProcessSockets( SessionMgrState *pState );
static int HandleNewClient( SessionMgrState *pState );
static int HandleVarNotification( SessionMgrState *pState );
static int HandleVarChanged( SessionMgrState *pState, VAR_HANDLE hVar );
static int HandleClientRequest( SessionMgrState *pState, fd_set *read_fds );
static int ReadClientRequest( SessionMgrState *pState, int fd );
static int ReadBasicAuthRequest( int fd, BasicAuthRequest *bar );
static int ReadSessionId( int fd,
                          SessionRequest *pReq,
                          char *session,
                          size_t len );

static int ProcessClientRequest( SessionMgrState *pState,
                                 SessionRequest *pRequest,
                                 int fd );
static int ProcessRequestNewSession( SessionMgrState *pState,
                                     int fd,
                                     SessionRequest *pReq,
                                     SessionResponse *pResp );

static int ProcessRequestNewSessionFromToken( SessionMgrState *pState,
                                              int fd,
                                              SessionRequest *pReq,
                                              SessionResponse *pResp );

static int ProcessRequestDeleteSession( SessionMgrState *pState,
                                        int fd,
                                        SessionRequest *pReq,
                                        SessionResponse *pResp );
static int ProcessRequestValidateSession( SessionMgrState *pState,
                                          int fd,
                                          SessionRequest *pReq,
                                          SessionResponse *pResp );
static int CheckPassword( const char* user,
                          const char* password,
                          uid_t *uid );
static int CheckUser( SessionMgrState *pState, char *user );

static int SetupTimer( int s );
static int HandlePrintRequest( SessionMgrState *pState, int32_t id );
static SessionInfo *FindSession( SessionMgrState *pState,
                                 char *username,
                                 char *reference );
static SessionInfo *FindSessionById( SessionMgrState *pState,
                                     char *pSessionId );
static SessionInfo *NewSession( SessionMgrState *pState,
                                char *username,
                                char *reference );

static int GetSessionToken( char *buf, size_t len );
static int CheckTimeout( SessionMgrState *pState );
static void DeleteSession( SessionMgrState *pState, SessionInfo *pSessionInfo );
static int DeleteAllSessions( SessionMgrState *pState );
static int PrintSessions( SessionMgrState *pState, int fd );

static int UpdateSession( SessionMgrState *pState,
                          SessionResponse *pResp,
                          char *username,
                          char *reference,
                          uid_t uid );

static int CheckAuthToken( SessionMgrState *pState,
                           char *token,
                           uid_t *uid,
                           char *username,
                           size_t len );

static int SetVar( var *pVar, uint16_t val );
static size_t StrVarLen( var *pVar );
static int AllocStrVar( var *pVar, size_t len );
static int FreeStrVar( var *pVar );

/*==============================================================================
        Private file scoped variables
==============================================================================*/
/*! session manager state object */
static SessionMgrState state;

/*! session variables */
static const SessionVars session_vars[] = {
    {SESSION_INFO_NAME, &state.sessionInfo, NOTIFY_PRINT},
    {SESSION_TIMEOUT_NAME, &state.sessionTimeout, NOTIFY_MODIFIED},
    {SESSION_AUTOEXTEND_NAME, &state.autoExtend, NOTIFY_MODIFIED},
    {SESSION_AUDIT_NAME, &state.audit, NOTIFY_MODIFIED},
    {SESSION_ENABLE_NAME, &state.sessionEnable, NOTIFY_MODIFIED},
    {SESSION_AUDIENCE_NAME, &state.audience, NOTIFY_MODIFIED},
    {SESSION_ISSUER_NAME, &state.issuer, NOTIFY_MODIFIED},
    {SESSION_KEYSTORE_NAME, &state.keystore, NOTIFY_MODIFIED},
    {SESSION_USERLIST_NAME, &state.users, NOTIFY_MODIFIED}
};

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the session manager

    The main function starts the session manager process and waits for
    messages from clients

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return none

==============================================================================*/
int main(int argc, char **argv)
{
    int result = EINVAL;
    int i;
    int len;

    /* default variable values */
    InitVar16 vars[] =
    {
        { &state.sessionEnable, 1 },
        { &state.autoExtend, 0 },
        { &state.audit, 0 },
        { &state.sessionTimeout, DEFAULT_SESSION_TIMEOUT },
        { &state.sessionInfo, 0 }
    };

    /* list of string variables to allocate */
    var *strvars[] =
    {
        &state.issuer, &state.audience, &state.keystore, &state.users
    };

    /* remove any previous session manager API endpoint */
    unlink( SESSION_MANAGER_NAME );

    /* initialize the Session Manager State */
    memset( &state, 0, sizeof (SessionMgrState));

    /* get length of variable initializers */
    len = sizeof( vars ) / sizeof( vars[0] );
    for ( i = 0; i < len ; i++ )
    {
        SetVar( vars[i].pVar, vars[i].val );
    }

    /* allocate config strings */
    len = sizeof( strvars ) / sizeof( strvars[0] );
    for ( i = 0 ; i < len ; i++ )
    {
        AllocStrVar( strvars[i], 256 );
    }

    /* Process the command line options */
    ProcessOptions( argc, argv, &state );

    /* set up an abnormal termination handler */
    SetupTerminationHandler();

    /* get a handle to the variable server */
    state.hVarServer = VARSERVER_Open();

    /* set up varserver notifications */
    if ( SetupNotifications( &state ) == EOK )
    {
        /* set up timer */
        if ( SetupTimer( TIMER_S ) == EOK )
        {
            result = SessionMgrInit( &state );
            while ( 1 )
            {
                result = ProcessSockets( &state );
            }

            unlink(SESSION_MANAGER_NAME);
        }
    }

    /* deallocate config strings */
    len = sizeof( strvars ) / sizeof( strvars[0] );
    for ( i = 0 ; i < len ; i++ )
    {
        FreeStrVar( strvars[i] );
    }

    /* close connection to varserver */
    if ( state.hVarServer != NULL )
    {
        if ( VARSERVER_Close( state.hVarServer ) == EOK )
        {
            state.hVarServer = NULL;
        }
    }

    return result == EOK ? 0 : 1;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h]\n"
                " [-v] : verbose mode\n"
                " [-h] : display this help\n",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the SessionMgrState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the Session Manager state object

    @return none

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], SessionMgrState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "vh";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        result = EOK;

        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'h':
                    usage( argV[0] );
                    exit( 1 );
                    break;

                case 'v':
                    pState->verbose = true;
                    break;

                default:
                    break;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  SetupTerminationHandler                                                   */
/*!
    Set up an abnormal termination handler

    The SetupTerminationHandler function registers a termination handler
    function with the kernel in case of an abnormal termination of this
    process.

==============================================================================*/
static void SetupTerminationHandler( void )
{
    static struct sigaction sigact;

    memset( &sigact, 0, sizeof(sigact) );

    sigact.sa_sigaction = TerminationHandler;
    sigact.sa_flags = SA_SIGINFO;

    sigaction( SIGTERM, &sigact, NULL );
    sigaction( SIGINT, &sigact, NULL );

}

/*============================================================================*/
/*  TerminationHandler                                                        */
/*!
    Abnormal termination handler

    The TerminationHandler function will be invoked in case of an abnormal
    termination of this process.  The termination handler closes
    the connection with the variable server.

@param[in]
    signum
        The signal which caused the abnormal termination (unused)

@param[in]
    info
        pointer to a siginfo_t object (unused)

@param[in]
    ptr
        signal context information (ucontext_t) (unused)

==============================================================================*/
static void TerminationHandler( int signum, siginfo_t *info, void *ptr )
{
    /* signum, info, and ptr are unused */
    (void)signum;
    (void)info;
    (void)ptr;

    syslog( LOG_ERR, "Abnormal termination of Session Manager\n" );
    if ( VARSERVER_Close( state.hVarServer ) == EOK )
    {
        state.hVarServer = NULL;
    }

    unlink(SESSION_MANAGER_NAME);

    exit( 1 );
}

/*============================================================================*/
/*  SetupTimer                                                                */
/*!
    Set up a timer

    The SetupTimer function sets up a timer to periodically decrement the
    session timeout counter.

    @param[in]
        s
            Timer tick rate (in seconds)

    @retval EOK timer set up ok
    @retval other error from timer_create or timer_settime

==============================================================================*/
static int SetupTimer( int s )
{
    struct sigevent te;
    struct itimerspec its;
    time_t secs = (time_t)s;
    timer_t *timerID;
    int result = EINVAL;
    static timer_t timer = 0;
    int rc;

    timerID = &timer;

    /* Set and enable alarm */
    te.sigev_notify = SIGEV_SIGNAL;
    te.sigev_signo = TIMER_NOTIFICATION;
    te.sigev_value.sival_int = 1;
    rc = timer_create(CLOCK_REALTIME, &te, timerID);
    if ( rc == 0 )
    {
        its.it_interval.tv_sec = secs;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = secs;
        its.it_value.tv_nsec = 0;
        rc = timer_settime(*timerID, 0, &its, NULL);
        result = ( rc == 0 ) ? EOK : errno;
    }
    else
    {
        result = errno;
    }

    return result;
}

/*============================================================================*/
/*  SetVar                                                                    */
/*!
    Set a variable value

    The SetVar function sets a VARTYPE_UINT16 variable to the
    specified value.

    @param[in]
        pVar
            pointer to the var to set

    @param[in]
        val
            value to set

    @retval EOK the variable type, length and value were set
    @retval EINVAL invalid arguments

==============================================================================*/
static int SetVar( var *pVar, uint16_t val )
{
    int result = EINVAL;

    if ( pVar != NULL )
    {
        pVar->obj.type = VARTYPE_UINT16;
        pVar->obj.len = sizeof( uint16_t );
        pVar->obj.val.ui = val;
        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  StrVarLen                                                                 */
/*!
    Check the length of a string variable

    The StrVarLen function calculates the length of the
    specified string variable.  If the specified variable
    is not a string variable, the function will return 0.

    @param[in]
        pVar
            pointer to the var to calculate the length for

    @retval length of the string variable
    @retval 0 if the variable is not a string variable

==============================================================================*/
static size_t StrVarLen( var *pVar )
{
    size_t len = 0;

    if ( ( pVar != NULL ) &&
         ( pVar->obj.type == VARTYPE_STR ) &&
         ( pVar->obj.val.str != NULL ) )
    {
        len = strlen( pVar->obj.val.str );
    }

    return len;
}

/*============================================================================*/
/*  AllocStrVar                                                               */
/*!
    Allocate memory for a string variable

    The AllocStrVar function sets up the specified variable as a
    string variable and allocates memory for the string with the
    specified length

    @param[in]
        pVar
            pointer to the var to initialize

    @param[in]
        len
            maximum length of the string (including NUL terminator)

    @retval EOK string was allocated successfully
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
static int AllocStrVar( var *pVar, size_t len )
{
    int result = EINVAL;

    if ( pVar != NULL )
    {
        pVar->obj.type = VARTYPE_STR;
        pVar->obj.val.str = calloc(1 , len );
        if ( pVar->obj.val.str != NULL )
        {
            pVar->obj.len = len;
            result = EOK;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  FreeStrVar                                                                */
/*!
    Free memory for a string variable

    The FreeStrVar function deallocates the memory for the string
    var that was allocated with AllocStrVar

    @param[in]
        pVar
            pointer to the string var to deallocate

    @param[in]
        len
            maximum length of the string (including NUL terminator)

    @retval EOK string was allocated successfully
    @retval ENOTSUP not a string variable
    @retval EINVAL invalid arguments

==============================================================================*/
static int FreeStrVar( var *pVar )
{
    int result = EINVAL;

    if ( pVar != NULL )
    {
        if ( pVar->obj.type == VARTYPE_STR )
        {
            if ( pVar->obj.val.str != NULL )
            {
                free( pVar->obj.val.str );
                pVar->obj.val.str = NULL;
                pVar->obj.len = 0;
            }

            result = EOK;
        }
        else
        {
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  SessionMgrInit                                                            */
/*!
    Initialize the session manager

    The SessionMgrInit function initializes the session manager
    to accept connections from clients.

    @param[in]
        pState
            pointer to the Session Manager State

    @retval EOK session manager initialized ok
    @retval EINVAL invalid argument
    @retval other error from socket and bind system calls

==============================================================================*/
static int SessionMgrInit( SessionMgrState *pState )
{
    int result = EINVAL;
    struct sockaddr_un server;
    int rc;

    if ( pState != NULL )
    {
        /* create a listening socket */
        pState->sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (pState->sock < 0)
        {
            result = errno;
        }
        else
        {
            server.sun_family = AF_UNIX;
            strcpy(server.sun_path, SESSION_MANAGER_NAME);
            rc = bind( pState->sock,
                       (struct sockaddr *) &server,
                       sizeof(struct sockaddr_un));

            if ( rc < 0 )
            {
                result = errno;
            }
            else
            {
                /* accept incoming connections */
                listen( pState->sock, 5);

                /* add the Session Manager socket to the read fds set */
                result = UpdateFDSet( pState );
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  SetupNotifications                                                        */
/*!
    Set up varserver variable notifications

    The SetupNotifications function initializes the session manager
    to accept connections from clients.

    @param[in]
        pState
            pointer to the Session Manager State

    @retval EOK session manager initialized ok
    @retval EINVAL invalid argument
    @retval EBADF cannot get varserver notification file descriptor
    @retval other error from socket and bind system calls

==============================================================================*/
static int SetupNotifications( SessionMgrState *pState )
{
    int result = EINVAL;
    int rc;
    size_t n = sizeof session_vars / sizeof session_vars[0];
    size_t i;
    char *pName;
    var *pVar;
    NotificationType notifyType;

    if ( pState != NULL )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        for ( i = 0; i < n ; i++ )
        {
            pName = session_vars[i].pName;
            pVar = session_vars[i].pVar;
            notifyType = session_vars[i].notifyType;

            if ( ( pVar != NULL ) &&
                 ( pName != NULL ) )
            {
                /* get variable reference */
                pVar->hdl = VAR_FindByName( pState->hVarServer, pName );
                if ( pVar->hdl != VAR_INVALID )
                {
                    /* get initial value */
                    rc = VAR_Get( pState->hVarServer,
                                  pVar->hdl,
                                  &pVar->obj );
                    if ( rc != EOK )
                    {
                        result = rc;
                    }

                    /* set up notifications */
                    if ( notifyType != NOTIFY_NONE )
                    {
                        rc = VAR_Notify( pState->hVarServer,
                                         pVar->hdl,
                                         notifyType );
                        if ( rc != EOK )
                        {
                            result = rc;
                        }
                    }
                }
            }
        }

        /* get a file descriptor to receive varserver signals on */
        pState->varserver_fd = VARSERVER_Signalfd( 0 );
        if ( pState->varserver_fd > 0 )
        {
            FD_SET( pState->varserver_fd, &pState->read_fds );
        }
        else
        {
            result = EBADF;
        }
    }

    return result;
}

/*============================================================================*/
/*  NewClient                                                                 */
/*!
    Create a new Session Manager client

    The NewClient function creates a new session manager client.
    It tries to get a client from the free client list, but if none
    are available it will allocate memory for one from the heap.
    It stores the specified file descriptor in the new client object

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            file descriptor for the new session manager client

    @retval EOK new client created ok
    @retval EINVAL invalid arguments
    @retval ENOMEM memory allocation failure

==============================================================================*/
static int NewClient( SessionMgrState *pState, int fd )
{
    int result = EINVAL;
    SessionMgrClient *p;

    if ( pState != NULL )
    {
        /* assume everything is ok until it isn't */
        result = EOK;

        if ( pState->pFreeList != NULL )
        {
            /* get Session Manager client object from the free list */
            p = pState->pFreeList;
            pState->pFreeList = p->pNext;
        }
        else
        {
            /* allocate memory for the Session Manager client */
            p = calloc( 1, sizeof( SessionMgrClient ));
        }

        if ( p != NULL )
        {
            /* insert the new client at the beginning of the client list */
            p->pNext = pState->pClientList;
            pState->pClientList = p;

            /* set the new client file descriptor */
            p->fd = fd;

            /* update the file descriptor set */
            result = UpdateFDSet( pState );
        }
        else
        {
            /* memory allocation failure */
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  DeleteClient                                                              */
/*!
    Delete a Session Manager client

    The DeleteClient function deletes a session manager client when it
    disconnects.  The Session Manager client object is moved from the
    active client list to the free client list and its file descriptor
    is cleared.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            file descriptor for the session manager client to be removed

    @retval EOK client deleted ok
    @retval EINVAL invalid arguments
    @retval ENOENT client not found

==============================================================================*/
static int DeleteClient( SessionMgrState *pState, int fd )
{
    int result = EINVAL;
    SessionMgrClient *p;
    SessionMgrClient *lastp = NULL;

    if ( pState != NULL )
    {
        /* assume client not found until it is */
        result = ENOENT;

        p = pState->pClientList;
        while ( p != NULL )
        {
            if ( p->fd == fd )
            {
                if ( p == pState->pClientList )
                {
                    /* remove the first client */
                    pState->pClientList = p->pNext;
                }
                else
                {
                    /* remove client from mid-list */
                    lastp->pNext = p->pNext;
                }

                /* store the client on the free list */
                p->pNext = pState->pFreeList;
                pState->pFreeList = p;
                p->fd = -1;
                result = UpdateFDSet( pState );
                break;
            }

            lastp = p;
            p = p->pNext;
        }
    }

    return result;
}

/*============================================================================*/
/*  UpdateFDSet                                                              */
/*!
    Update the file descriptor set for all clients

    The UpdateFDSet function updates the session manager read_fds set
    of all the file descriptors to select() on.
    After this function runs, the SessionMgrState read_fds has the list
    of file descriptors to select on, and the maxfd field has the
    maximum file descriptor to select on.

    This function should be called at the start of the service, and
    after any client has connected or disconneced

    @param[in]
        pState
            pointer to the Session Manager State


    @retval EOK session manager read fds list has been updated
    @retval EINVAL invalid arguments

==============================================================================*/
static int UpdateFDSet( SessionMgrState *pState )
{
    int result = EINVAL;
    SessionMgrClient *p;

    if ( pState != NULL )
    {
        FD_ZERO( &pState->read_fds );
        pState->maxfd = -1;

        if ( pState->varserver_fd != -1 )
        {
            FD_SET( pState->varserver_fd, &pState->read_fds );
            if ( pState->varserver_fd > pState->maxfd )
            {
                pState->maxfd = pState->varserver_fd;
            }
        }

        if ( pState->sock != -1 )
        {
            FD_SET( pState->sock, &pState->read_fds );
            if ( pState->sock > pState->maxfd )
            {
                pState->maxfd = pState->sock;
            }
        }

        p = pState->pClientList;
        while ( p != NULL )
        {
            if ( p->fd != -1 )
            {
                FD_SET( p->fd, &pState->read_fds );
                if ( p->fd > pState->maxfd )
                {
                    pState->maxfd = p->fd;
                }
            }

            p = p->pNext;
        }

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  ProcessSockets                                                            */
/*!
    Process all incoming requests

    The ProcessSockets function waits on the sockets in the read_fds
    object for any changes to read status.  If any sockets need attention
    the function will process the pending requests on the sockets.

    @param[in]
        pState
            pointer to the Session Manager State

    @retval EOK session manager sockets processed ok
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessSockets( SessionMgrState *pState )
{
    int result = EINVAL;
    int activity;
    fd_set read_fds;

    if ( pState != NULL )
    {
        result = EOK;

        read_fds = pState->read_fds;

        /* wait for an activity on one of the sockets */
        activity = select( pState->maxfd + 1,
                           &read_fds,
                           NULL,
                           NULL,
                           NULL );
        if ( activity )
        {
            if ( FD_ISSET( pState->sock, &read_fds ) )
            {
                /* handle a new client connection */
                result = HandleNewClient( pState );
            }
            else if ( FD_ISSET( pState->varserver_fd, &read_fds ) )
            {
                /* handle a variable notification */
                result = HandleVarNotification( pState );
            }
            else
            {
                /* handle a client session request */
                result = HandleClientRequest( pState, &read_fds );
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleNewClient                                                           */
/*!
    Handle a new client connection

    The HandleNewClient function handles a new client connection by
    creating a new client and adding the client to the client list.

    @param[in]
        pState
            pointer to the Session Manager State

    @retval EOK new client successfully added
    @retval ENOMEM memory allocation failure
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleNewClient( SessionMgrState *pState )
{
    int result = EINVAL;
    int fd;

    if ( pState != NULL )
    {
        if ( pState->sock >= 0 )
        {
            fd = accept( pState->sock, NULL, NULL );
            if ( fd != -1 )
            {
                /* create a new client */
                result = NewClient( pState, fd );
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleVarNotification                                                     */
/*!
    Handle a varserver notification

    The HandleVarNotification function handles a notification from the variable
    server.

    @param[in]
        pState
            pointer to the Session Manager State

    @retval EOK varserver notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleVarNotification( SessionMgrState *pState )
{
    int result = EINVAL;
    int signum;
    int32_t sigval;
    VAR_HANDLE hVar;

    if ( pState != NULL )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        signum = VARSERVER_WaitSignalfd( pState->varserver_fd, &sigval );
        if ( signum == SIG_VAR_TIMER )
        {
            /* check session timeout */
            result = CheckTimeout( pState );
        }
        else if ( signum == SIG_VAR_PRINT )
        {
            result = HandlePrintRequest( pState, sigval );
        }
        else if ( signum == SIG_VAR_MODIFIED )
        {
            hVar = (VAR_HANDLE)sigval;
            result = HandleVarChanged( pState, hVar );
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleVarChanged                                                          */
/*!
    Handle a varserver change notification

    The HandleVarChangeed function handles a change notification
    from the variable server.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        hVar
            handle to the variable which was changed

    @retval EOK varserver change notification handled successfully
    @retval ENOTSUP variable not found
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleVarChanged( SessionMgrState *pState, VAR_HANDLE hVar )
{
    int result = EINVAL;
    size_t n = sizeof session_vars / sizeof session_vars[0];
    size_t i;
    var *pVar;

    if ( pState != NULL )
    {
        for ( i = 0; i < n; i++ )
        {
            pVar = session_vars[i].pVar;
            if ( pVar != NULL )
            {
                if ( pVar->hdl == hVar )
                {
                    /* get the changed value */
                    result = VAR_Get( pState->hVarServer,
                                      hVar,
                                      &pVar->obj );
                    break;
                }
            }
        }

        if ( ( hVar == pState->sessionEnable.hdl ) &&
             ( pState->sessionEnable.obj.val.ui == 0 ) )
        {
            result = DeleteAllSessions( pState );
        }
    }

    return result;
}

/*============================================================================*/
/*  HandlePrintRequest                                                        */
/*!
    Handle a varserver print request notification

    The HandlePrintRequest function handles a print request notification
    from the variable server.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        id
            print notification identifier

    @retval EOK print request notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandlePrintRequest( SessionMgrState *pState, int32_t id )
{
    int result = EINVAL;
    VAR_HANDLE hVar;
    int fd;

    if ( pState != NULL )
    {
        /* open a print session */
        if ( VAR_OpenPrintSession( pState->hVarServer,
                                   id,
                                   &hVar,
                                   &fd ) == EOK )
        {
            result = ENOENT;

            if ( hVar == pState->sessionInfo.hdl )
            {
                PrintSessions( pState, fd );
            }

            /* Close the print session */
            result = VAR_ClosePrintSession( pState->hVarServer,
                                            id,
                                            fd );
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleClientRequest                                                       */
/*!
    Handle a client request

    The HandleClientRequest function iterates through the client list
    to check if each client has made a request.  If a request is pending
    the ProcessClientRequest function is invoked.

    @param[in]
        pState
            pointer to the Session Manager State

    @retval EOK client requests handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleClientRequest( SessionMgrState *pState, fd_set *read_fds )
{
    int result = EINVAL;
    int rc;
    int fd;
    SessionMgrClient *p;

    if ( pState != NULL )
    {
        result = EOK;

        p = pState->pClientList;
        while ( p != NULL )
        {
            fd = p->fd;
            p = p->pNext;

            if ( FD_ISSET( fd, read_fds ) )
            {
                rc = ReadClientRequest( pState, fd );
                if ( rc != EOK )
                {
                    /* zero tolerance for misbehaving clients */
                    close( fd );
                    DeleteClient( pState, fd );
                    result = rc;
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ReadClientRequest                                                         */
/*!
    Read a client request

    The ReadClientRequest function reads a request for the specified
    client and passes it to the processing function

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            the file descriptor of the requesting client

    @retval EOK client request handled successfully
    @retval EBADMSG invalid session request message format
    @retval EINVAL invalid arguments

==============================================================================*/
static int ReadClientRequest( SessionMgrState *pState, int fd )
{
    SessionRequest req;
    ssize_t n;
    ssize_t len;

    int result = EINVAL;

    if ( pState != NULL )
    {
        len = sizeof( SessionRequest );
        n = read( fd, &req, len );
        if ( n == len )
        {
            if ( ( req.id == SESSION_MANAGER_ID ) &&
                 ( req.version == SESSION_MANAGER_VERSION ) )
            {
                result = ProcessClientRequest( pState, &req, fd );
            }
            else
            {
                result = EBADMSG;
            }
        }
        else
        {
            result = EBADMSG;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessClientRequest                                                      */
/*!
    Process a client request

    The ProcessClientRequest function processes a request for the specified
    client.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        pReq
            pointer to the SessionRequest object

    @param[in]
        fd
            the file descriptor of the requesting client

    @retval EOK client request handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessClientRequest( SessionMgrState *pState,
                                 SessionRequest *pReq,
                                 int fd )
{
    int result = EINVAL;
    SessionResponse resp;
    ssize_t len;
    ssize_t n;

    if ( ( pState != NULL ) &&
         ( pReq != NULL ) &&
         ( fd > 0 ) )
    {
        memset( &resp, 0, sizeof( SessionResponse ) );

        if ( pState->sessionEnable.obj.val.ui != 0 )
        {
            switch( pReq->type )
            {
                case SESSION_REQUEST_NEW:
                    result = ProcessRequestNewSession( pState,
                                                       fd,
                                                       pReq,
                                                       &resp );
                    break;

                case SESSION_REQUEST_NEW_FROM_TOKEN:
                    result = ProcessRequestNewSessionFromToken( pState,
                                                                fd,
                                                                pReq,
                                                                &resp );
                    break;

                case SESSION_REQUEST_DELETE:
                    result = ProcessRequestDeleteSession( pState,
                                                          fd,
                                                          pReq,
                                                          &resp );
                    break;

                case SESSION_REQUEST_VALIDATE:
                    result = ProcessRequestValidateSession( pState,
                                                            fd,
                                                            pReq,
                                                            &resp );
                    break;

                default:
                    resp.responseCode = ENOTSUP;
                    result = EOK;
                    break;
            }
        }
        else
        {
            resp.responseCode = EACCES;
            result = EOK;
        }

        resp.id = SESSION_MANAGER_ID;
        resp.version = SESSION_MANAGER_VERSION;

        len = sizeof(SessionResponse);
        n = write( fd, &resp, len);
        if ( n == len )
        {
            result = EOK;
        }
        else
        {
            result = EIO;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessRequestNewSession                                                  */
/*!
    Process a client NewSession request

    The ProcessRequestNewSession function processes a NewSession request
    for the specified client.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            file descriptor to read the BasicAuthRequest from

    @param[in]
        pReq
            pointer to the SessionRequest object

    @param[in,out]
        pResp
            pointer to the SessionResponse object

    @retval EOK client request handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessRequestNewSession( SessionMgrState *pState,
                                     int fd,
                                     SessionRequest *pReq,
                                     SessionResponse *pResp )
{
    int result = EINVAL;
    BasicAuthRequest bar;
    int rc;
    uid_t uid;

    if ( ( pState != NULL ) &&
         ( pReq != NULL ) &&
         ( pResp != NULL ) &&
         ( fd != -1 ) )
    {
        memset( pResp, 0, sizeof( SessionResponse ));

        result = ReadBasicAuthRequest( fd, &bar );
        if ( result == EOK )
        {
            /* see if the user in the user list */
            if ( CheckUser( pState, bar.username ) == EOK )
            {
                /* check if password is valid for the specified user */
                rc = CheckPassword( bar.username,
                                    bar.password,
                                    &uid );
                if ( rc == EOK )
                {
                    /* create or update a session */
                    result = UpdateSession( pState,
                                            pResp,
                                            bar.username,
                                            bar.reference,
                                            uid );
                }
                else
                {
                    pResp->responseCode = EACCES;
                }
            }
            else
            {
                pResp->responseCode = EACCES;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessRequestNewSession                                                  */
/*!
    Process a client NewSession request

    The ProcessRequestNewSession function processes a NewSession request
    for the specified client.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            file descriptor to read the reference and token from

    @param[in]
        pReq
            pointer to the SessionRequest object

    @param[in,out]
        pResp
            pointer to the SessionResponse object

    @retval EOK client request handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessRequestNewSessionFromToken( SessionMgrState *pState,
                                              int fd,
                                              SessionRequest *pReq,
                                              SessionResponse *pResp )
{
    int result = EINVAL;
    int rc;
    char sessionref[SESSION_MAX_REFERENCE_LEN+1];
    char token[SESSION_MAX_TOKEN_LEN+1];
    char username[SESSION_MAX_USERNAME_LEN+1];

    size_t len;
    size_t n;
    uid_t uid;

    if ( ( pState != NULL ) &&
         ( pReq != NULL ) &&
         ( pResp != NULL ) &&
         ( fd != -1 ) )
    {
        memset( pResp, 0, sizeof( SessionResponse ));

        len = sizeof sessionref;
        n = read( fd, sessionref, len );
        if ( n == len )
        {
            len = sizeof token;
            if ( pReq->payloadlen < len )
            {
                len = pReq->payloadlen;
                n = read( fd, token, len );
                if ( n == len )
                {
                    result = EOK;
                }
                else
                {
                    result = EBADMSG;
                }
            }
        }

        if ( result == EOK )
        {
            // to do - token validation
            rc = CheckAuthToken( pState,
                                 token,
                                 &uid,
                                 username,
                                 sizeof username );
            if ( rc == EOK )
            {
                /* create or update a session */
                result = UpdateSession( pState,
                                        pResp,
                                        username,
                                        sessionref,
                                        uid );

            }
            else
            {
                pResp->responseCode = EACCES;
            }
        }
        else
        {
            pResp->responseCode = EACCES;
        }
    }

    return result;
}

/*============================================================================*/
/*  UpdateSession                                                             */
/*!
    Update or Add a new session

    The UpdateSession function either refreshes an existing session or
    creates a new session for the given username/reference.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in,out]
        pResp
            pointer to the SessionResponse object

    @param[in]
        username
            pointer to the name of the user to add/update

    @param[in]
        reference
            pointer to the name of the reference to add/update

    @retval EOK client request handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int UpdateSession( SessionMgrState *pState,
                          SessionResponse *pResp,
                          char *username,
                          char *reference,
                          uid_t uid )
{
    int result = EINVAL;
    SessionInfo *pSessionInfo;

    if ( ( pState != NULL ) &&
         ( pResp != NULL ) &&
         ( username != NULL ) &&
         ( reference != NULL ) )
    {
        result = EOK;

        /* see if a session for this user/clientref already exists */
        pSessionInfo = FindSession( pState, username, reference );
        if ( pSessionInfo != NULL )
        {
            pResp->responseCode = EOK;

            /* reset the timeout */
            pSessionInfo->timeout = pState->sessionTimeout.obj.val.ui;

            /* get the user id */
            pSessionInfo->uid = uid;
            pResp->uid = uid;

            /* get the session id */
            strcpy(pResp->sessionId, pSessionInfo->sessionId);
        }
        else
        {
            /* create a new session */
            pSessionInfo = NewSession( pState, username, reference );
            if ( pSessionInfo != NULL )
            {
                pResp->responseCode = EOK;
                pSessionInfo->uid = uid;
                pResp->uid = uid;
                strcpy(pResp->sessionId, pSessionInfo->sessionId);
            }
            else
            {
                pResp->responseCode = EIO;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ReadBasicAuthRequest                                                      */
/*!
    Read a BasicAuthRequest object from the client

    The ReadBasicAuthRequest function reads a BasicAuthRequest object
    from the client.

    @param[in]
        fd
            file descriptor to read from

    @param[in]
        bar
            pointer to the BasicAuthRequest object to populate


    @retval EOK Basic Auth Request read successfully
    @retval EBADMSG inappropriate message length
    @retval EINVAL invalid arguments

==============================================================================*/
static int ReadBasicAuthRequest( int fd, BasicAuthRequest *bar )
{
    int result = EINVAL;
    size_t len;
    size_t n;

    if ( ( bar != NULL ) &&
         ( fd != -1 ) )
    {
        len = sizeof( BasicAuthRequest );
        n = read( fd, bar, len );
        result = ( n == len ) ? EOK : EBADMSG;
    }

    return result;
}

/*============================================================================*/
/*  ProcessRequestDeleteSession                                               */
/*!
    Process a client DeleteSession request

    The ProcessRequestDeleteSession function processes a DeleteSession request
    for the specified client.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            file descriptor to read the session id from

    @param[in]
        pReq
            pointer to the SessionRequest object

    @param[in,out]
        pResp
            pointer to the SessionResponse object

    @retval EOK client request handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessRequestDeleteSession( SessionMgrState *pState,
                                        int fd,
                                        SessionRequest *pReq,
                                        SessionResponse *pResp )
{
    int result = EINVAL;
    SessionInfo *pSessionInfo;
    char sessionId[SESSION_ID_LEN+1];

    if ( ( pState != NULL ) &&
         ( pReq != NULL ) &&
         ( pResp != NULL ) &&
         ( fd != -1 ) )
    {
        result = ReadSessionId( fd, pReq, sessionId, sizeof sessionId );
        if ( result == EOK )
        {
            strcpy( pResp->sessionId, sessionId );

            pSessionInfo = FindSessionById( pState, sessionId );
            if ( pSessionInfo != NULL )
            {
                DeleteSession( pState, pSessionInfo );
                pResp->responseCode = EOK;
            }
            else
            {
                pResp->responseCode = ENOENT;
            }
        }
        else
        {
            pResp->responseCode = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessRequestValidateSession                                             */
/*!
    Process a client ValidateSession request

    The ProcessRequestValidateSession function processes a ValidateSession
    requestfor the specified client.

    @param[in]
        pState
            pointer to the Session Manager State

    @param[in]
        fd
            file descriptor to read the session id from

    @param[in]
        pReq
            pointer to the SessionRequest object

    @param[in,out]
        pResp
            pointer to the SessionResponse object

    @retval EOK client request handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessRequestValidateSession( SessionMgrState *pState,
                                          int fd,
                                          SessionRequest *pReq,
                                          SessionResponse *pResp )
{
    int result = EINVAL;
    SessionInfo *pSessionInfo;
    char sessionId[SESSION_ID_LEN+1];

    if ( ( pState != NULL ) &&
         ( pReq != NULL ) &&
         ( pResp != NULL ) )
    {
        memset( pResp, 0, sizeof( SessionResponse ));

        result = ReadSessionId( fd, pReq, sessionId, sizeof sessionId );
        if ( result == EOK )
        {
            strcpy( pResp->sessionId, sessionId );

            pSessionInfo = FindSessionById( pState, sessionId );
            if ( pSessionInfo != NULL )
            {
                pResp->responseCode = EOK;

                if ( pState->autoExtend.obj.val.ui != 0 )
                {
                    /* reset timeout back to its default value */
                    pSessionInfo->timeout = pState->sessionTimeout.obj.val.ui;
                }

                pResp->uid = pSessionInfo->uid;
            }
            else
            {
                pResp->responseCode = EACCES;
            }
        }
        else
        {
            pResp->responseCode = EACCES;
        }
    }

    return result;
}

/*============================================================================*/
/*  ReadSessionId                                                             */
/*!
    Read a session identifier from the client

    The ReadSessionId function reads a session identifier from
    a client

    @param[in]
        fd
            file descriptor to read from

    @param[in]
        pReq
            pointer to the SessionRequest object which contains the
            payload length to read

    @param[in,out]
        session
            pointer to the location to store the session identifier

    @param[in]
        len
            length of the buffer to store the session identifier

    @retval EOK session identifier was read from the client
    @retval EBADMSG invalid message length
    @retval EINVAL invalid arguments

==============================================================================*/
static int ReadSessionId( int fd,
                          SessionRequest *pReq,
                          char *session,
                          size_t len )
{
    int result = EINVAL;
    size_t n;

    if ( ( pReq != NULL ) &&
         ( pReq->payloadlen < len ) &&
         ( fd != -1 ) &&
         ( session != NULL ) &&
         ( len > 0 ) )
    {
        n = read( fd, session, pReq->payloadlen );
        if ( n == pReq->payloadlen )
        {
            /* NUL terminate the session identifier */
            session[n] = 0;
            result = EOK;
        }
        else
        {
            result = EBADMSG;
        }
    }

    return result;
}

/*============================================================================*/
/*  CheckPassword                                                             */
/*!
    Check a user's access

    The CheckPassword function checks the specified user's password
    against the entry in the /etc/passwd or /etc/shadow file for
    that user.  If a match is found the user id for that user is
    returned

    @param[in]
        user
            pointer to the user's name

    @param[in]
        password
            pointer to the user's password

    @param[in,out]
        uid
            pointer to a location to store the user identifier

    @retval EOK user is authenticated
    @retval EINVAL invalid arguments
    @retval ENOENT user does not exist
    @retval EACCES permission denied

==============================================================================*/
static int CheckPassword( const char* user,
                          const char* password,
                          uid_t *uid )
{
    int result = EINVAL;
    struct passwd *passwordEntry = NULL;
    struct spwd *shadowEntry = NULL;
    char *encryptedPassword = NULL;
    char *pwd = NULL;

    if ( ( user != NULL ) &&
         ( password != NULL ) &&
         ( uid != NULL ))
    {
        passwordEntry = getpwnam( user );
        if ( passwordEntry != NULL )
        {
            pwd = passwordEntry->pw_passwd;

            if ( strcmp( pwd, "x" ) != 0 )
            {
                encryptedPassword = crypt( password, pwd );
            }
            else
            {
                shadowEntry = getspnam( user );
                if ( shadowEntry != NULL )
                {
                    pwd = shadowEntry->sp_pwdp;
                    encryptedPassword = crypt( password, pwd );
                }
            }

            if ( ( encryptedPassword != NULL ) &&
                 ( pwd != NULL ) )
            {
                if ( strcmp( encryptedPassword, pwd ) == 0 )
                {
                    *uid = passwordEntry->pw_uid;
                    result = EOK;
                }
                else
                {
                    result = EACCES;
                }
            }
            else
            {
                result = EPERM;
            }
        }
        else
        {
            /* user does not exist */
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  FindSession                                                               */
/*!
    Search for a session

    The FindSession function searches the active session list for a
    session which matches the user name and password contained in the
    SessionRequest

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        pReq
            pointer to the Session Request containing the user name and
            client reference

    @retval pointer to the SessionInfo object which matched the query
    @retval NULL no SessionInfo object matched the query

==============================================================================*/
static SessionInfo *FindSession( SessionMgrState *pState,
                                 char *username,
                                 char *reference )
{
    SessionInfo *pSession = NULL;

    if ( ( pState != NULL ) &&
         ( username != NULL ) &&
         ( reference != NULL ) )
    {
        pSession = pState->pActiveSessions;
        while ( pSession != NULL )
        {
            if ( ( strcmp( username, pSession->username ) == 0 ) &&
                 ( strcmp( reference, pSession->reference ) == 0 ) )
            {
                break;
            }

            pSession = pSession->pNext;
        }
    }

    return pSession;
}

/*============================================================================*/
/*  FindSessionById                                                           */
/*!
    Search for a session

    The FindSession function searches the active session list for a
    session which matches the specified session identifier.

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        pSessionId
            pointer to the Session identifier to search for

    @retval pointer to the SessionInfo object which matched the query
    @retval NULL no SessionInfo object matched the query

==============================================================================*/
static SessionInfo *FindSessionById( SessionMgrState *pState,
                                     char *pSessionId )
{
    SessionInfo *pSession = NULL;

    if ( ( pState != NULL ) &&
         ( pSessionId != NULL ) )
    {
        pSession = pState->pActiveSessions;
        while ( pSession != NULL )
        {
            if ( strcmp( pSessionId, pSession->sessionId ) == 0 )
            {
                break;
            }

            pSession = pSession->pNext;
        }
    }

    return pSession;
}

/*============================================================================*/
/*  NewSession                                                                */
/*!
    Create a new session

    The NewSession function creates a new session and adds it to the
    active session list

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        username
            pointer to the user name for the new session

    @param[in]
        reference
            pointer to the reference for the new session

    @retval pointer to the created SessionInfo object
    @retval NULL could not create the session

==============================================================================*/
static SessionInfo *NewSession( SessionMgrState *pState,
                                char *username,
                                char *reference )
{
    SessionInfo *pSession = NULL;
    char sessionId[ SESSION_ID_LEN + 1 ];

    if ( ( pState != NULL ) &&
         ( username != NULL ) &&
         ( reference != NULL ) )
    {
        /* generate a session token */
        if ( GetSessionToken( sessionId, SESSION_ID_LEN ) == EOK )
        {
            /* nul terminate the session token */
            sessionId[SESSION_ID_LEN] = 0;

            if ( pState->pFreeSessions != NULL )
            {
                /* get the session info object from the free session list */
                pSession = pState->pFreeSessions;
                pState->pFreeSessions = pSession->pNext;
                memset( pSession, 0, sizeof(SessionInfo));
            }
            else
            {
                pSession = calloc( 1, sizeof( SessionInfo ));
            }

            if ( pSession != NULL )
            {
                /* copy the session username and client reference */
                strcpy( pSession->username, username );
                strcpy( pSession->reference, reference );
                strcpy( pSession->sessionId, sessionId );

                /* set the session timeout */
                pSession->timeout = pState->sessionTimeout.obj.val.ui;

                /* add the new session to the head of the active session list */
                pSession->pNext = pState->pActiveSessions;
                pState->pActiveSessions = pSession;

                if ( pState->audit.obj.val.ui != 0 )
                {
                    syslog( LOG_INFO,
                            "NewSession: %s/%s (%8.8s)",
                            pSession->username,
                            pSession->reference,
                            pSession->sessionId );
                }
            }
        }
    }

    return pSession;
}

/*============================================================================*/
/*  GetSessionToken                                                           */
/*!
    Generate a session token

    The GetSessionToken function generates a session of the specified length
    and stores it into the specifier buffer (which mush have enough allocated
    space for the specified length).

    @param[in]
        buf
            pointer to the Session token buffer

    @param[in]
        len
            length of the token to generate (excluding NUL terminator)

    @retval EOK token was successfully generated
    @retval EINVAL invalid arguments
    @retval ENOTSUP token generation failed

==============================================================================*/
static int GetSessionToken( char *buf, size_t len )
{
    int result = EINVAL;
    ssize_t n;
    size_t i;
    size_t l;
    const char set[] = "IA7Ra2Hsyh"
                       "SdtB5jYboQZ1lGfE4NrMmx8WzV"
                       "uCJeK3pciD6XqT9Lvk0PFwgUOn";
    if ( buf != NULL )
    {
        l = sizeof(set) - 1;

        n = getrandom( buf, len, 0 );
        if ( (size_t)n == len )
        {
            for( i = 0 ; i < len ; i++ )
            {
                buf[i] = set[buf[i] % l];
            }

            result = EOK;
        }
        else
        {
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  CheckTimeout                                                              */
/*!
    Check all sessions for timeout

    The CheckTimeout function iterates through all the active sessions,
    checking each for timeout.  If a session has timed out it will
    be deleted.

    @param[in]
        pState
            pointer to the Session Manager state

    @retval EOK timeout check was completed
    @retval EINVAL invalid arguments

==============================================================================*/
static int CheckTimeout( SessionMgrState *pState )
{
    int result = EINVAL;
    SessionInfo *pSessionInfo;
    SessionInfo *p;

    if ( pState != NULL )
    {
        result = EOK;

        if ( pState->sessionTimeout.obj.val.ui != 0 )
        {
            pSessionInfo = pState->pActiveSessions;
            while( pSessionInfo != NULL )
            {
                p = pSessionInfo;
                pSessionInfo = pSessionInfo->pNext;

                p->timeout -= TIMER_S;
                if ( p->timeout <= 0 )
                {
                    /* remove the session from the active session list */
                    DeleteSession( pState, p );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  DeleteSession                                                             */
/*!
    Delete the specified session

    The DeleteSession function deletes the specified session
    and moves it into the free session list.

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        pSessionInfo
            pointer to the session object to delete

==============================================================================*/
static void DeleteSession( SessionMgrState *pState, SessionInfo *pSessionInfo )
{
    SessionInfo *p;
    SessionInfo *pLast = NULL;
    bool found = false;

    if ( ( pState != NULL ) &&
         ( pSessionInfo != NULL ) )
    {
        if ( pSessionInfo == pState->pActiveSessions )
        {
            pState->pActiveSessions = pSessionInfo->pNext;
            found = true;
        }
        else
        {
            /* start search from the second session in the list */
            pLast = pState->pActiveSessions;
            p = pLast->pNext;

            /* iterate until we find the session */
            while ( p != NULL )
            {
                if ( p == pSessionInfo )
                {
                    pLast->pNext = p->pNext;
                    found = true;
                    break;
                }

                pLast = p;
                p = p->pNext;
            }
        }

        if ( found == true )
        {
            /* place the deleted session on the free session list */
            pSessionInfo->pNext = pState->pFreeSessions;
            pState->pFreeSessions = pSessionInfo;

            if ( pState->audit.obj.val.ui != 0 )
            {
                syslog( LOG_INFO,
                        "Session %s:%s terminated",
                        pSessionInfo->username,
                        pSessionInfo->reference );
            }
        }
    }
}

/*============================================================================*/
/*  DeleteAllSessions                                                         */
/*!
    Delete all active sessions

    The DeleteAllSessions function deletes all the active sessions
    and moves them into the free session list

    @param[in]
        pState
            pointer to the Session Manager state

    @retval EOK all sessions deleted
    @retval EINVAL invalid arguments

==============================================================================*/
static int DeleteAllSessions( SessionMgrState *pState )
{
    int result = EINVAL;
    SessionInfo *p;
    SessionInfo *pSessionInfo;

    if ( pState != NULL )
    {
        p = pState->pActiveSessions;
        while ( p != NULL )
        {
            pSessionInfo = p;
            p = p->pNext;

            /* put the session onto the free list */
            pSessionInfo->pNext = pState->pFreeSessions;
            pState->pFreeSessions = pSessionInfo;
        }

        /* clear the active list */
        pState->pActiveSessions = NULL;

        if ( pState->audit.obj.val.ui != 0 )
        {
            syslog( LOG_INFO, "All sessions deleted" );
        }

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  PrintSessions                                                             */
/*!
    Print the active sessions

    The PrintSessions function prints out the username, client reference,
    and time remaining for all of the active sessions.

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        fd
            output file descriptor

==============================================================================*/
static int PrintSessions( SessionMgrState *pState, int fd )
{
    int result = EINVAL;
    SessionInfo *pSessionInfo;
    int count = 0;

    if ( ( pState != NULL ) &&
         ( fd >= 0 ) )
    {
        pSessionInfo = pState->pActiveSessions;

        result = EOK;

        dprintf( fd, "[");
        while( pSessionInfo != NULL )
        {
            if ( count )
            {
                dprintf( fd, "," );
            }

            dprintf( fd,
                     "{ \"user\": \"%s\", "
                     "\"userid\": \"%d\","
                     "\"reference\": \"%s\","
                     "\"session\": \"%8.8s\","
                     "\"remaining\": %d }",
                     pSessionInfo->username,
                     pSessionInfo->uid,
                     pSessionInfo->reference,
                     pSessionInfo->sessionId,
                     pSessionInfo->timeout );

            count++;
            pSessionInfo = pSessionInfo->pNext;
        }

        dprintf( fd, "]");
    }

    return result;
}

/*============================================================================*/
/*  CheckAuthToken                                                            */
/*!
    Check the validity of the authentication token

    The CheckAuthToken function checks the validity of the authentication
    token and retrieves its associated user.

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        token
            pointer to the authentication token

    @param[in]
        uid
            pointer to a location to store the user identifier

    @param[in]
        username
            pointer to a buffer to store the username

    @param[in]
        len
            maximum allowed length of the username

    @retval EOK - user authenticated
    @retval EINVAL - invalid arguments
    @retval EACCES - access denied

==============================================================================*/
static int CheckAuthToken( SessionMgrState *pState,
                           char *token,
                           uid_t *uid,
                           char *username,
                           size_t len )
{
    int result = EINVAL;
    TJWT *jwt;
    int64_t now = time( NULL );
    JWTClaims *claims = NULL;
    struct passwd *passwordEntry = NULL;
    size_t l;

    if ( ( pState != NULL ) &&
         ( token != NULL ) &&
         ( username != NULL ) &&
         ( len > 0 ) &&
         ( uid != NULL ) )
    {
        /* assume access is denied until we know otherwise */
        result = EACCES;

        jwt = TJWT_Init();
        if ( jwt != NULL )
        {
            /* set the key store where we look for public validation keys */
            if ( StrVarLen( &pState->keystore ) != 0 )
            {
                TJWT_SetKeyStore( jwt, pState->keystore.obj.val.str );
            }

            if ( StrVarLen( &pState->issuer ) != 0 )
            {
                /* expect a specific issuer */
                TJWT_ExpectIssuer( jwt, pState->issuer.obj.val.str );
            }

            if ( StrVarLen( &pState->audience ) != 0 )
            {
                /* expect a specific audience */
                TJWT_ExpectAudience( jwt, pState->audience.obj.val.str );
            }

            if ( TJWT_Validate( jwt, now, token ) == EOK )
            {
                claims = TJWT_GetClaims( jwt );
                if ( ( claims != NULL ) &&
                     ( claims->sub != NULL ) )
                {
                    /* username is stored in JWT subject */
                    /* check if user is in the users list */
                    if ( CheckUser( pState, claims->sub ) == EOK )
                    {
                        /* check if user exists */
                        passwordEntry = getpwnam( claims->sub );
                        if ( passwordEntry != NULL )
                        {
                            /* check username length */
                            l = strlen( claims->sub );
                            if ( l < len )
                            {
                                /* copy username to caller */
                                strcpy( username, claims->sub );

                                /* set user id */
                                *uid = passwordEntry->pw_uid;

                                /* access is allowed! */
                                result = EOK;
                            }
                        }
                    }
                }
            }
            else
            {
                if ( pState->verbose == true )
                {
                    TJWT_PrintSections( jwt, STDERR_FILENO );
                    TJWT_PrintClaims( jwt, STDERR_FILENO );
                    TJWT_OutputErrors( jwt, STDERR_FILENO );
                }

                result = EACCES;
            }

            TJWT_Free( jwt );
        }
        else
        {
            result = EACCES;
        }
    }

    return result;
}

/*============================================================================*/
/*  CheckUser                                                                 */
/*!
    Check if the specified user is in the user list

    The CheckUser function checks if the specified user is found within
    the user list

    @param[in]
        pState
            pointer to the Session Manager state

    @param[in]
        user
            pointer to the user to search for

    @retval EOK - user found
    @retval EINVAL - invalid arguments
    @retval EACCES - access denied

==============================================================================*/
static int CheckUser( SessionMgrState *pState, char *user )
{
    int result = EINVAL;
    char buf[BUFSIZ];
    size_t len;
    char *save;
    char *pUser;

    if ( ( pState != NULL ) &&
         ( user != NULL ) )
    {
        /* assume user is not allowed until they are */
        result = EACCES;

        /* check if user is allowed */
        len = StrVarLen( &pState->users );
        if ( ( len != 0 ) &&
             ( len < sizeof buf ) )
        {
            /* copy the user list into a working buffer so we can
               split it on the comma delimiter */
            strcpy( buf, pState->users.obj.val.str );

            /* iterate through each user in the user list and
               see if it matches the requested user */
            for (pUser = strtok_r(buf, ",", &save);
                pUser != NULL;
                pUser = strtok_r(NULL, ",", &save))
            {
                /* check for user match */
                if ( strcmp( pUser, user ) == 0 )
                {
                    /* matching user found */
                    result = EOK;
                    break;
                }
            }
        }
    }

    return result;
}

/*! @}
 * end of sessionmgr group */
