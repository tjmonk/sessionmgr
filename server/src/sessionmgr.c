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
#include <shadow.h>
#include <crypt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/un.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <varserver/varserver.h>
#include <sessionmgr/sessionmgr.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*! name of variable get get session information */
#ifndef SESSION_INFO_NAME
#define SESSION_INFO_NAME "/sys/session/info"
#endif

/*! name of variable to enable session handling */
#ifndef SESSION_ENABLE_NAME
#define SESSION_ENABLE_NAME "/sys/session/enable"
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

    /*! handle to the session info variable */
    VAR_HANDLE hSessionInfo;

    /*! handle to the session manager enable variable */
    VAR_HANDLE hSessionEnable;

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

} SessionMgrState;

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
static int HandleClientRequest( SessionMgrState *pState, fd_set *read_fds );
static int ReadClientRequest( SessionMgrState *pState, int fd );
static int ProcessClientRequest( SessionMgrState *pState,
                                 SessionRequest *pRequest,
                                 int fd );
static int CheckPassword( const char* user, const char* password );

/*==============================================================================
        Private file scoped variables
==============================================================================*/
static SessionMgrState state;

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

    /* initialize the Session Manager State */
    memset( &state, 0, sizeof (SessionMgrState));

    /* Process the command line options */
    ProcessOptions( argc, argv, &state );

    /* set up an abnormal termination handler */
    SetupTerminationHandler();

    /* get a handle to the variable server */
    state.hVarServer = VARSERVER_Open();

    /* set up varserver notifications */
    SetupNotifications( &state );

    result = SessionMgrInit( &state );
    while ( 1 )
    {
        result = ProcessSockets( &state );
    }

    unlink(SESSION_MANAGER_NAME);

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
    VARSERVER_Close( state.hVarServer );

    unlink(SESSION_MANAGER_NAME);

    exit( 1 );
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
                printf( "Socket has name %s\n", server.sun_path );
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

    if ( pState != NULL )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        /* set up print notification for optional session info variable */
        pState->hSessionInfo = VAR_FindByName( pState->hVarServer,
                                               SESSION_INFO_NAME );
        if ( pState->hSessionInfo != VAR_INVALID )
        {
            /* set up print notification */
            rc = VAR_Notify( pState->hVarServer,
                             pState->hSessionInfo,
                             NOTIFY_PRINT );
            if ( rc != EOK )
            {
                result = rc;
            }
        }

        /* set up modified notification for optional session enable variable */
        pState->hSessionEnable = VAR_FindByName( pState->hVarServer,
                                                 SESSION_ENABLE_NAME );
        if ( pState->hSessionEnable != VAR_INVALID )
        {
            /* set up modified notification */
            rc = VAR_Notify( pState->hVarServer,
                             pState->hSessionEnable,
                             NOTIFY_MODIFIED );
            if ( rc != EOK )
            {
                result = rc;
            }
        }

        /* get a file descriptor to receive varserver signals on */
        pState->varserver_fd = VARSERVER_Signalfd();
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

    printf("NewClient\n");
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

    printf("DeleteClient\n");
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

    printf("ProcessSockets\n");
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
            printf("activity detected\n");
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

    printf("HandleNewClient\n");
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

    if ( pState != NULL )
    {

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

    printf("HandleClientRequest\n");
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

    printf("ReadClientRequest\n");
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
    int rc;

    printf("ProcessClientRequest\n");
    if ( ( pState != NULL ) &&
         ( pReq != NULL ) &&
         ( fd > 0 ) )
    {
        printf("username: %s\n", pReq->username);
        printf("password: %s\n", pReq->password);
        printf("reference: %s\n", pReq->reference);

        resp.id = SESSION_MANAGER_ID;
        resp.version = SESSION_MANAGER_VERSION;

        rc = CheckPassword( pReq->username, pReq->password );
        if ( rc == EOK )
        {
            resp.type = SESSION_RESPONSE_OK;
            strcpy(resp.response,"user authenticated");
        }
        else
        {
            resp.type = SESSION_RESPONSE_FAILED;
            strcpy(resp.response,"access denied");
        }

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
/*  CheckPassword                                                             */
/*!
    Check a user's access

    The CheckPassword function checks the specified user's password
    against the entry in the /etc/passwd or /etc/shadow file for
    that user.

    @param[in]
        user
            pointer to the user's name

    @param[in]
        password
            pointer to the user's password

    @retval EOK user is authenticated
    @retval EINVAL invalid arguments
    @retval ENOENT user does not exist
    @retval EACCES permission denied

==============================================================================*/
static int CheckPassword( const char* user, const char* password )
{
    int result = EINVAL;
    struct passwd *passwordEntry = NULL;
    struct spwd *shadowEntry = NULL;
    char *encryptedPassword = NULL;
    char *pwd = NULL;

    if ( ( user != NULL ) &&
         ( password != NULL ) )
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
                result = strcmp( encryptedPassword, pwd ) == 0 ? EOK : EACCES;
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

/*! @}
 * end of sessionmgr group */
