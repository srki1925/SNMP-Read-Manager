/*++

Copyright (c) Microsoft Corporation

Module Name: wsnmputil.cpp

*/

/*	

	Izvorni kod zajedno sa definicijama i implementacijama je preuzet iz
	Microsoft Corporation SDK primeraka programa radi razvoja sopstvenih
	menadzerskih i agentskih aplikacija.
	Kod je doradjen/preradjen da bude u skladu sa zanovljenim pravilima VC++2010/
	VC++2012 standarda u vidu odradjenih dodatnih kastovanja i/ili dodavanja
	dodatnih argumenata za deprecated funkcije.
	Takodje su dodani komentari na srpskom jeziku kao dopuna radi pojasnjenja
	radnji koje obavljaju pojedine funkcije i delovi koda su enkapsulirani
	u (ne)neophodne dodatne funkcije cisto radi omogucenja brzeg razvoja
	novih aplikacija.

	Ovaj izvorni kod ima ubacene sve neophodne funkcije za rad sa slanjem
	zahteva i primanjem odgovora (od snmp agenta) preko SNMP protokola 
	implementirane su mogucnosti SNMPv1/v2 koje omogucuju GET, GET_NEXT,
	WALK, GET_BULK, SET, SUB_TREE. 

*/

//							NAPOMENA!!!
//
//		dati izvorni kod radi samo na Windows i to na svim platformama
//		od windows-a NT 5.0 (Windows 2000) pa na dalje.
//		Kod nije prenosiv na druge sisteme zbog koriscenja ugradjenog
//		winSnmp API radi olaksane realizacije istog.


#include  <stdio.h>
#include  <string.h>
#include  <stdlib.h>
#include  <winsock2.h>
#include  <winsnmp.h>
#include  <snmp.h>
#include  <mgmtapi.h>

#include  "wsnmputil.h"

/*

	Dodane su pragme radi ucitavanja dll zato sto su primeri u originalu
	bili zamisljeni da se izvrsni kod generise putem nmake-a tj. pokretanjem
	shell scripte koja radi ukljucivanje ispod navedenih dll-ova.

	Zbog problema striktne administracije fakultativne racunarske opreme
	odluceno je da se dodaju u predprocesiranje radi smanjenja slozenosti
	buducih implementacija.

*/

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wsnmp32.lib")
#pragma comment(lib, "mgmtapi.lib")
#pragma comment(lib, "snmpapi.lib")
#pragma comment(lib, "oldnames.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS


GlobalVars    gVars;


//dodana funkcija radi pojednostavljenja ciscenja 
//zauzetih resursa
//abstract: free all allocated resources
//input: smiVALUE* lvalue
//output: BOOL status
BOOL FreeMemory(smiVALUE* lvalue)
{
	int i;

	for (i = 0; i < gVars.oidCount; i++)
	{
		if (gVars.pszOid[i])
			SnmpUtilMemFree(gVars.pszOid[i]);
	}

	if (gVars.pAgentStrAddr)
		SnmpUtilMemFree(gVars.pAgentStrAddr);

	if (gVars.pAgentStrAddr != NULL)
		SnmpUtilMemFree(gVars.pAgentCommunity);

	if (gVars.pSetValue)
		SnmpUtilMemFree(gVars.pSetValue);

	if (
		((lvalue->syntax == SNMP_SYNTAX_OCTETS)
			|| (lvalue->syntax == SNMP_SYNTAX_BITS)
			|| (lvalue->syntax == SNMP_SYNTAX_OPAQUE)
			|| (lvalue->syntax == SNMP_SYNTAX_IPADDR)
			|| (lvalue->syntax == SNMP_SYNTAX_OID))
		&& lvalue->value.string.ptr)
	{
		SnmpUtilMemFree(lvalue->value.string.ptr);
	}

	return TRUE;
}

/*
	Vrsi otvaranje nove snmp sesije sa zadatim agentom na
	standardnom portu protokola 161 i dodaje pravo pristupa
	(community) koji se koriste radi get/set metoda
*/
//
//abstract: open a WinSNMP session
//input :   PSNMP_MGR_SESSION pSession
//output:   TRUE if successful, FALSE if not.
//        
BOOL    OpenWinSNMPSession ( PSNMP_MGR_SESSION pSession )
{

    smiOCTETS smiCommunity;

    if ( pSession == NULL )
        return ( FALSE );

    // create a remote session
    pSession->hSnmpSession = SnmpOpen( pSession->hWnd, WM_SNMP_INCOMING );

    if ( SNMP_FAILURE( pSession->hSnmpSession ) )
        return ( FALSE );

    if ( gVars.pAgentStrAddr != NULL )
    {
        
        // create a remote agent entity
        pSession->hAgentEntity = SnmpStrToEntity( pSession->hSnmpSession, 
                                             (char*)(&gVars.agentAddr));     

        if ( SNMP_FAILURE( pSession->hAgentEntity ) )
            return ( FALSE );
        
        // attach timeout specified with agent
        SnmpSetTimeout( pSession->hAgentEntity, gVars.nTimeOut / 10 );

        // attach retries specified with agent
        SnmpSetRetry( pSession->hAgentEntity, gVars.nRetries );

        // create local manager entity
        pSession->hManagerEntity = SnmpStrToEntity(
                                     pSession->hSnmpSession,
                                     DEFAULT_ADDRESS_IP );
        if ( SNMP_FAILURE( pSession->hManagerEntity ) )
            return ( FALSE );

        // attach timeout specified with manager
        SnmpSetTimeout( pSession->hManagerEntity, gVars.nTimeOut / 10 );

        // attach retries specified with manager
        SnmpSetRetry( pSession->hManagerEntity, gVars.nRetries );  

    } // end of if ( pAgentStrAddr )

        // validate pointer
    if ( gVars.pAgentCommunity != NULL) 
    {

        // transfer community string
        smiCommunity.ptr = (smiLPBYTE)gVars.pAgentCommunity;
        smiCommunity.len = gVars.pAgentCommunity ? lstrlen( gVars.pAgentCommunity) : 0;

        // obtain context from community string
        pSession->hViewContext = SnmpStrToContext(
                                     pSession->hSnmpSession,
                                     &smiCommunity
                                    );

        // validate context handle
        if ( SNMP_FAILURE( pSession->hViewContext) ) 
            return ( FALSE );

    }

    // success
    return (TRUE);
  
}  //end of OpenWinSNMP Session



//
// abstarct:   close a WinSNMP session
// input :     pointer to a SNMP_MGR_SESSION
// output:     TRUE if successful, FALSE if not.    
//
BOOL    CloseWinSNMPSession ( PSNMP_MGR_SESSION pSession )
{

    BOOL fOk = TRUE;
    SNMPAPI_STATUS status;

    // validate session ptr
    if ( pSession == NULL )
        return FALSE;

    // check if window opened
    if ( pSession->hWnd != (HWND)NULL ) 
    {
        // destroy notification window
        fOk = DestroyNotificationWindow( pSession );
    }

    // close view context
    if ( pSession->hViewContext  != (HSNMP_CONTEXT) NULL)
    {
        SnmpFreeContext( pSession->hViewContext );
    }

    // check if agent entity allocated
    if ( pSession->hAgentEntity != (HSNMP_ENTITY)NULL ) 
    {

        // close the entity handle
        status = SnmpFreeEntity( pSession->hAgentEntity );

        // validate status
        if ( status == SNMPAPI_FAILURE ) 
        {
            // failure
            fOk = FALSE;
        }

        // re-initialize
        pSession->hAgentEntity = (HSNMP_ENTITY)NULL;
    }

    // check if manager entity allocated
    if ( pSession->hManagerEntity != (HSNMP_ENTITY)NULL ) 
    {

        // close the entity handle
        status = SnmpFreeEntity( pSession->hManagerEntity );

        // validate status
        if ( status == SNMPAPI_FAILURE ) 
        {
    
            // failure
            fOk = FALSE;
        }

        // re-initialize
        pSession->hManagerEntity = (HSNMP_ENTITY)NULL;
    }

   
    // check if session allocated
    if ( pSession->hSnmpSession != (HSNMP_SESSION)NULL ) 
    {

        // close the winsnmp session
        status = SnmpClose( pSession->hSnmpSession );

        // validate status
        if ( status == SNMPAPI_FAILURE )
        {
            // failure
            fOk = FALSE;
        }

        // re-initialize
        pSession->hSnmpSession = (HSNMP_SESSION)NULL;
    }

    return fOk;

} // end of CloseWinSNMPSession



//
// abstarct: create a notification window, which will receive WinSnmp messages.
//           The window will remain hidden.
//
// input:    pointer to PSNMP_MGR_SESSION
// 
// output:
// TRUE     if successful in creating the window
// FALSE    if not successful in creating the window handle.
//
BOOL    CreateNotificationWindow( PSNMP_MGR_SESSION pSession)
{

    BOOL    fOk;
    WNDCLASS wc;
	
    if ( pSession == NULL )
    {    
        return FALSE;
    }

    // initialize notification window class
    wc.lpfnWndProc   = (WNDPROC)NotificationWndProc;
    wc.lpszClassName = NOTIFICATION_CLASS;
    wc.lpszMenuName  = NULL;
    wc.hInstance     = gVars.g_hInst;
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = NULL;
    wc.cbWndExtra    = sizeof(PSNMP_MGR_SESSION);
    wc.cbClsExtra    = 0;
    wc.style         = 0;    // register class
    fOk = RegisterClass(&wc);

    if (!fOk) 
    {
        PrintDbgMessage( "snmputil: RegisterClass returned %d.\n", GetLastError() );
        return (FALSE);
    }
    // create notification window
    pSession->hWnd = CreateWindow(
                      NOTIFICATION_CLASS,
                      "SNMP Util Class",                // pointer to window name
                      WS_OVERLAPPEDWINDOW,              // window style
                      0,                                // horizontal position of window
                      0,                                // vertical position of window
                      0,                                // window width
                      0,                                // window height
                      NULL,                             // handle to parent or owner window
                      NULL,                             // handle to menu or child-window identifier
                      gVars.g_hInst,                    // handle to application instance
                      NULL                              // pointer to window-creation data
                    );

    // validate window handle
    if ( pSession->hWnd != NULL ) 
    {
        // store pointer to session in window
        SetWindowLongPtr( pSession->hWnd, 0, (INT_PTR)pSession );

        // success
        fOk = TRUE;
    } 
    else 
    {     
        // failure
        fOk = FALSE;
    }

    return fOk;
    
} // end of CreateNotificationWindow



//
// abstract: destroy the notification window.
// input:    PSNMP_MGR_SESSION pSession
// output:   result of the operation.
//
BOOL    DestroyNotificationWindow( PSNMP_MGR_SESSION pSession )
{
    BOOL    fOk;

    // destroy the notification window.
    return( fOk = DestroyWindow( pSession->hWnd ) );
} // end of DestroyNotificationWindow



//
// abstract
//
//    Callback that processes WinSNMP notifications.
//
// input:
//
//  hWnd - window handle.
//
//  uMsg - message identifier.
//
//  wParam - first message parameter.
//
//  lParam - second message parameter.
//
// return Values:
//
//    The return value is the result of the message processing and
//    depends on the message sent.
//
LRESULT
CALLBACK
NotificationWndProc(
    HWND   hWnd,
    UINT   uMsg,
    WPARAM wParam,
    LPARAM lParam
    )
{
    // check for winsnmp notification
    if (uMsg == WM_SNMP_INCOMING) 
    {
        
        PSNMP_MGR_SESSION pSession;

        // retrieve session pointer from window
        pSession = (PSNMP_MGR_SESSION)GetWindowLongPtr(hWnd, 0);

        // validate session ptr
        if ( pSession == NULL )
            return (LRESULT)0;

        //Ako je doslo do prijema response poruke od agenta sa
		//PostMassage izbacujemo poruku na konzolu

        // process notification message
        if ( ProcessNotification( pSession ) ) 
        {
            // post message to break out of message pump
            PostMessage( pSession->hWnd, WM_SNMP_DONE, (WPARAM)0, (LPARAM)0 );
        }

        return (LRESULT)0;

    } 
    else 
    {
        // forward all other messages to windows
        return DefWindowProc(hWnd, uMsg, wParam, lParam);
    }

} // end of NotificationWndProc


/*
	Vrsimo obradu primljene poruke i proveru da agent mozda nije
	poslao error da smo pogresno zadali komandu...
*/
//
// abstract: we got a notification message back, process it
// input :   pointer to manager session
// output:   TRUE if successful, FALSE if not.
//
BOOL    ProcessNotification( PSNMP_MGR_SESSION pSession )
{

    BOOL           fDone = TRUE;
    SNMPAPI_STATUS status;
    HSNMP_ENTITY   hAgentEntity   = (HSNMP_ENTITY)NULL;
    HSNMP_ENTITY   hManagerEntity = (HSNMP_ENTITY)NULL;
    HSNMP_CONTEXT  hViewContext   = (HSNMP_CONTEXT)NULL;
    smiINT32       nPduType; 
    smiINT32       nRequestId;
    char           szBuf[1024];

    // validate pointer
    if ( pSession == NULL )
        return FALSE;

    // retrieve message
    status = SnmpRecvMsg(
                pSession->hSnmpSession,
                &hAgentEntity,
                &hManagerEntity,
                &hViewContext,
                &pSession->hPdu
                );

    // validate return code
    if ( status != SNMPAPI_FAILURE )
    {                
        // retrieve pdu data
        status = SnmpGetPduData(
                    pSession->hPdu,
                    &nPduType,
                    &nRequestId,
                    &pSession->nErrorStatus,
                    &pSession->nErrorIndex,
                    &pSession->hVbl
                    );
    
        // validate return code            
        if ( status != SNMPAPI_FAILURE ) 
        {

            // process reponse to request
            if (nPduType == SNMP_PDU_RESPONSE) 
            {  
                // validate context information
                if (( pSession->nRequestId   == nRequestId ) &&
                    ( pSession->hViewContext == hViewContext ) &&
                    ( pSession->hAgentEntity == hAgentEntity ) &&
                    ( pSession->hManagerEntity == hManagerEntity ) ) 
                {

                    // if we hit the end of tree, break.
                    if ( PrintVarBind( pSession ) == FALSE )
                        gVars.fDone = TRUE;
                
                } 
                else 
                {
                    // continue
                    fDone = FALSE;
                }

            } 
            else if (nPduType == SNMP_PDU_TRAP) 
            {

                status = SnmpEntityToStr( hAgentEntity, 1024, szBuf );
                if ( ! (SNMP_FAILURE ( status )  ) )
                    PrintDbgMessage( "Agent : %s \n\n", szBuf );

                // Process the TRAP                
                ParseAndPrintv2Trap( pSession );

            } 
            else 
            {
                PrintDbgMessage( "snmputil: Invalid PDU type %d \n", nPduType );
                // continue
                fDone = FALSE;
            }

        } 
        else 
            PrintDbgMessage( "snmputil: SnmpGetPduData returned error %d \n", SnmpGetLastError( pSession->hSnmpSession ) );
      
        
        // release temporary entity
        SnmpFreeEntity(hAgentEntity);

        // release temporary entity
        SnmpFreeEntity(hManagerEntity);

        // release temporary context
        SnmpFreeContext(hViewContext);

    } 
    
    // release pdu
    FreeVblandPdu( pSession );
    
    return fDone;

}  //end of ProcessNotification



// 
//    abstarct: Sit in an infinite loop waiting for traps.
//    input :   pointer to a snmp mgr session
//    output:   TRUE when a WM_QUIT is sent to pSession->hWnd
//
BOOL    WaitForTraps( PSNMP_MGR_SESSION pSession )
{
    SNMPAPI_STATUS    status;

    if ( pSession == NULL )
        return( FALSE );

    // re-iniialize.

    pSession->nError = 0;

    // register
    status = SnmpRegister( 
                 pSession->hSnmpSession,
                (HSNMP_ENTITY)NULL,     // hManagerEntity
                (HSNMP_ENTITY)NULL,     // hAgentEntity
                (HSNMP_CONTEXT)NULL,    // hViewContext
                (smiLPCOID)NULL,        // notification
                SNMPAPI_ON
                );

    if ( SNMP_FAILURE( status ) )
    {
        pSession->nError = SnmpGetLastError( pSession->hSnmpSession );
        PrintDbgMessage( "snmputil: Failed in SnmpRegister %d \n", pSession->nError );
        return (FALSE);
    }
    else
    {
        printf("WSnmpUtil: listening for traps...\n");
        while( ProcessAgentResponse ( pSession ) )
        {                
        }
    }
    return TRUE;

} //end of WaitForTraps



//
//  abstract: Keep looking for an SNMP message.
//  input:    pointer to SNMP manager session
//  output:   TRUE if successful, FALSE otherwise.
//
BOOL ProcessAgentResponse( PSNMP_MGR_SESSION pSession )
{

    MSG        uMsg;
    BOOL    fOk = FALSE;

    if ( pSession == NULL )
        return FALSE;
	/*	
		Uzimamo poruku koja sledeca pristize u datoj sesiji i 
		sa DispatchMessage radimo bacanje na Q sesije da ju
		pokupimo sa PostMessage i izbacimo na ispis korisniku
	*/
    // get the next message for this session
    while ( GetMessage( &uMsg, pSession->hWnd, 0, 0) ) 
    {

        // check for private message
        if ( uMsg.message != WM_SNMP_DONE) 
        {
            TranslateMessage(&uMsg);
            DispatchMessage(&uMsg);
        } 
        else 
        {
            // success
            fOk = TRUE;
            break;
        }
    }

    return fOk;

} // end of ProcessAgentResponse



//
// abstract: Create a Vbl for different types of PDUS.
// input:    pSession pointer to manager session. pSession->hVbl will have the handle.
//           pOid      pointer to smiOID that will be used.
//           pValue      pointer to a value in a set request.
// output:   TRUE if successful, FALSE if not.
//
BOOL CreateVbl( PSNMP_MGR_SESSION pSession, smiOID *pOid, smiVALUE * pValue  )
{

    // check for NULL pointers
    if ( ( pOid == NULL )    ||
         ( pSession == NULL ) )
         return FALSE;

    // create the var bind list.
    pSession->hVbl = SnmpCreateVbl( pSession->hSnmpSession, 
                                      pOid, 
                                    ( ( pSession->nPduType == SNMP_PDU_SET ) ? pValue : NULL ) );

    if ( SNMP_FAILURE( pSession->hVbl ) )
        return FALSE;
    else
        return TRUE;
    
} //end of CreateVbl



// abstract: the routine will free the Vbl and the Pdu associated with a session.
// input:    pSession a pointer to the PSNMP_MGR_SESSION
// output:   none
//
void    FreeVblandPdu( PSNMP_MGR_SESSION pSession )
{
    if ( pSession == NULL )
        return;

    pSession->nError = SnmpFreeVbl( pSession->hVbl );
    if ( SNMP_FAILURE( pSession->nError ) )
    {
        pSession->nError = SnmpGetLastError( pSession->hSnmpSession );
        PrintDbgMessage( "snmputil: failure in SnmpFreeVbl %d \n ", pSession->nError );
    }


    pSession->nError = SnmpFreePdu( pSession->hPdu );
    if ( SNMP_FAILURE( pSession->nError ) )
    {
        pSession->nError = SnmpGetLastError( pSession->hSnmpSession );
        PrintDbgMessage( "snmputil: failure in SnmpFreePdu %d \n ", pSession->nError );
    }

} // end of FreeVblandPdu


//
// abstarct: create a needed PDU,  send the request and loop in the message loop 
//           within the ProcessAgentResponse function until the SNMP reply PDU is 
//           processed.
// input:    pointer to PSNMP_MGR_SESSION
// output:   status: TRUE if successful, FALSE otherwise.
//
BOOL    CreatePduSendRequest( PSNMP_MGR_SESSION pSession, smiVALUE *pValue )
{

    // check for the validity of the structure.
    if ( pSession == NULL )
        return (FALSE);

    // set the pdu type.
    switch ( gVars.operation )
    {
        case GET:
            pSession->nPduType = SNMP_PDU_GET;
            break;
        case GET_NEXT:
            pSession->nPduType = SNMP_PDU_GETNEXT;
            break;
        case WALK:
            pSession->nPduType = SNMP_PDU_GETNEXT;
            break;
        case SET:
            pSession->nPduType = SNMP_PDU_SET;
            break;
        case SUB_TREE:
            pSession->nPduType = SNMP_PDU_GETNEXT;
            break;
        case GET_BULK:
            pSession->nPduType = SNMP_PDU_GETBULK;
        default:
            break;
    }

    // first time around, walk: always use the first oid
    if ( ( gVars.nRequestId  == 1 ) && ( ( gVars.operation == WALK ) || ( gVars.operation == SUB_TREE ) ) ) // || ( gVars.operation == GET_BULK ) ) )
    {
        if ( SNMP_FAILURE ( SnmpStrToOid( gVars.pszOid[0] , &gVars.oid ) ) )
        {
            if ( SnmpMgrStrToOid( gVars.pszOid[0] , (AsnObjectIdentifier *)&gVars.oid ) == FALSE )
            {
                PrintDbgMessage( "snmputil: Failed in SnmpStrToOid( ) or SnmpMgrStrToOid( ) function ..\n" );
                return ( FALSE );
            }
        }
        else
        {
            // copy the var bind
            gVars.startOid = gVars.oid;
        }
    }

    // create the appropriate Varbind lists depending on the operation.
    if ( ( gVars.operation == WALK ) || ( gVars.operation == SUB_TREE ) )
    {
        if ( ( CreateVbl( pSession, &gVars.oid, NULL ) ) == FALSE )
            return ( FALSE );
    }
    else if ( ( gVars.operation == GET_NEXT ) || ( gVars.operation == GET ) )
    {
        
        if ( SNMP_FAILURE ( SnmpStrToOid( gVars.pszOid[ gVars.nRequestId - 1 ] , 
                                      &gVars.oid ) ) )
        {
            if ( SnmpMgrStrToOid( gVars.pszOid[gVars.nRequestId - 1] , (AsnObjectIdentifier *)&gVars.oid ) == FALSE )
            {
                PrintDbgMessage( "snmputil: Failed in SnmpStrToOid( ) or SnmpMgrStrToOid( ) function ..\n" );
                return ( FALSE );
            }
        }    
        
        if ( ( CreateVbl( pSession, &gVars.oid, NULL ) ) == FALSE )
                return ( FALSE );
                    
    }
    else if ( gVars.operation == SET ) 
    {        
        pSession->hVbl = SnmpCreateVbl( pSession->hSnmpSession,
                                        &gVars.oid,
                                        pValue
                                        );
       }
    
    else if ( gVars.operation == GET_BULK ) 
    {
        //CreateVbl first then add OIDs to the Vbl
        pSession->hVbl = 
            SnmpCreateVbl(  pSession->hSnmpSession,  // handle to the WinSNMP session 
                            NULL,                    // pointer to the variable name 
                            NULL                     // pointer to the value to associate with the variable 
                            );
        

        if ( SNMP_FAILURE( pSession->hVbl ) )
            return (FALSE);
        for (int i = 0; i < gVars.oidCount; i++)
        {
            //the very last gVars.oid in the loop will be freed later.
            if (i > 0) 
            {
                    SnmpFreeDescriptor ( SNMP_SYNTAX_OID, (smiLPOPAQUE)&gVars.oid);
            }

            if ( SNMP_FAILURE ( SnmpStrToOid( gVars.pszOid[i] , &gVars.oid ) ) )
            {
                if ( SnmpMgrStrToOid( gVars.pszOid[i] , (AsnObjectIdentifier *)&gVars.oid ) == FALSE )
                {
                    PrintDbgMessage( "snmputil: Failed in SnmpStrToOid( ) or SnmpMgrStrToOid( ) function ..\n" );
                    return ( FALSE );
                }
            }
            // append vb to Vbl
            if ( SNMP_FAILURE ( SnmpSetVb(pSession->hVbl,    0, &gVars.oid, NULL    ) ) )
            {
                PrintDbgMessage( "snmputil: Failed in SnmpSetVb( ) function ..\n" );
                return ( FALSE );
            }
        }
                
    }

    
    pSession->nRequestId = gVars.nRequestId++;

    // create a pdu using the parameters in pSession structure
    pSession->hPdu = SnmpCreatePdu( pSession->hSnmpSession,
                                      pSession->nPduType,
                                      pSession->nRequestId,
                                      ( ( gVars.operation == GET_BULK ) ? gVars.non_repeaters : 0 ),
                                      ( ( gVars.operation == GET_BULK ) ? gVars.max_repetitions : 0 ),
                                      pSession->hVbl );

    if ( SNMP_FAILURE ( pSession->hPdu ) )
    {
        PrintDbgMessage( "snmputil: Failed in creating PDU ..\n " );
        return (FALSE);
    }

    // send the message to the agent
    pSession->nError = SnmpSendMsg(    pSession->hSnmpSession,
                                        pSession->hManagerEntity,
                                        pSession->hAgentEntity,
                                        pSession->hViewContext,
                                        pSession->hPdu );

    if ( gVars.operation != SUB_TREE ) SnmpFreeDescriptor ( SNMP_SYNTAX_OID, (smiLPOPAQUE)&gVars.oid); 

    
    // check error status and return.
    if ( SNMP_FAILURE( pSession->nError ) )
    {
         
         pSession->nError = SnmpGetLastError( pSession->hSnmpSession );
         PrintDbgMessage( "snmputil: Failed in send message, Last Error %d \n", pSession->nError );
         FreeVblandPdu( pSession );
         return (FALSE);
    }
    else
    {

        FreeVblandPdu( pSession );
        return ( ProcessAgentResponse ( pSession ) );
    }

} //end of CreatePduSendRequest
