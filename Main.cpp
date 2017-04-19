#define _CRT_SECURE_NO_WARNINGS
#include  <stdio.h>
#include  <string.h>
#include  <stdlib.h>
#include  <winsock2.h>
#include  <winsnmp.h>
#include  <snmp.h>
#include  <mgmtapi.h>
#include  <strsafe.h>

#include "WSnmpUtil.h"


void UnosParametara();
void getNewRequest();

int main(int argc, char** argv) {
	
		PSNMP_MGR_SESSION	pSession = NULL;
		BOOL				result;
		int					i = 0;
		smiVALUE			lvalue;
		SNMPAPI_STATUS		status;
		BOOL				startedAsConsole = FALSE;

		WSADATA				wsaData;
		START_PARAMS		sp;


		int					numTries = 0;

		if (WSAStartup(0x202, &wsaData)) 
		{
			printf("WSAStartup failed with error: %d", WSAGetLastError());
			return -1;
		}

		
		
	
		if (argc < 2) {
			
			ParamEntry();
			startedAsConsole = TRUE;
		}
		else if (ParseCommandLine(argc, argv) == FALSE) {
			printf("\n\nUneli ste pogresne parametre program se izvrsava u konzolnom rezimu\n\n");
			startedAsConsole = TRUE;
			ParamEntry();
		}

		status = SnmpStartup(
			&sp.nMajorVersion,
			&sp.nMinorVersion,
			&sp.nLevel,
			&sp.nTranslateMode,
			&sp.nRetransmitMode
		);

		//ako je prosla inicijalizacija winSnmp API 
		//podesavamo verziju snmp protokola
		if (!SNMP_FAILURE(status))
		{
			if (gVars.version == FALSE)
				SnmpSetTranslateMode(SNMPAPI_UNTRANSLATED_V1);
			else
				SnmpSetTranslateMode(SNMPAPI_UNTRANSLATED_V2);
		}
		else
		{
			printf("Failed at setting translate mode...\nLine: %d", __LINE__);
			return -1;
		}

		//vrsimo alokaciju memorije za strukturu sesije
		pSession = (PSNMP_MGR_SESSION)SnmpUtilMemAlloc(sizeof(SNMP_MGR_SESSION));

		if (pSession == NULL)
		{
			printf("Failed at memory allocation for snmp_manager...\nLine: %d", __LINE__);
			return -1;
		}
		//pravimo prozor na koji cemo da slazemo poruke na Q i vrsimo ispis korisniku
		if (!CreateNotificationWindow(pSession))
		{
			printf("Failed to create notification window...\nLine: %d", __LINE__);
			return -1;
		}
		//otvaramo snmp sesiju sa agentom koji smo zadali
		if (OpenWinSNMPSession(pSession) == FALSE)
		{
			printf("Open session failed...\nLine: %d", __LINE__);
			return -1;
		}

		while (true) {
			if (startedAsConsole == TRUE && numTries > 0) {
				//UnosParametara();
				//gVars.oidCount = 0;
				gVars.nRequestId = 1;
				gVars.oidCount = 0;
				getNewRequest();
				
			}
			numTries++;
			if (startedAsConsole == FALSE && numTries > 0)
				break;
		

			switch (gVars.operation)
			{
			case GET:
			case GET_NEXT: //za svaki oid pravimo poseban request koji saljemo agentu
				for (i = 0; i < gVars.oidCount; i++)
					result = CreatePduSendRequest(pSession, NULL);
				break;
			case WALK:
				while (pSession->nErrorStatus == SNMP_ERROR_NOERROR)
				{
					if (!(result = CreatePduSendRequest(pSession, NULL)))
						break;
					if (gVars.fDone == TRUE)
						break;
				}
				break;
			case GET_BULK:
				result = CreatePduSendRequest(pSession, NULL);
				break;
			case SUB_TREE:
				while (pSession->nErrorStatus == SNMP_ERROR_NOERROR)
				{
					result = CreatePduSendRequest(pSession, NULL);

					// check the return status.
					if (result == FALSE)
						break;

					// check if we hit the end of the subtree ..
					if (gVars.fDone == TRUE)
						break;
				}
				break;
			case SET:		//set pdu se razlikuju u tome da sada mi specifikujemo vrednost na koji postavljamo vrednost objekta(oid)
				result = FALSE;
				gVars.doSet = TRUE;

				if (gVars.pSetValue != NULL)
				{
					gVars.operation = GET;
					result = CreatePduSendRequest(pSession, NULL);
				}

				if (result != FALSE)
				{
					gVars.operation = SET;
					
					// copy the object type. Ex: INT UINT32 etc..               
					lvalue.syntax = gVars.value.syntax;

					printf("Unesite vrednost: ");
					scanf("%d", lvalue.syntax);

					ConvertStringToSmiValue(&lvalue);

					result = CreatePduSendRequest(pSession, &lvalue);

					// check the error status on pSession.
					if (pSession->nErrorStatus != 0)
						PrintDbgMessage("Failed in setting the OID value ..\n");
					else
						PrintDbgMessage("Succeeded in setting the OID value ..\n");

				}
				break;
			}
		}//end while
		FreeMemory(&lvalue);
		DestroyNotificationWindow(pSession);

		CloseWinSNMPSession(pSession);

		if (pSession)
			SnmpUtilMemFree(pSession);

		SnmpCleanup();

		WSACleanup();
		char tmp;
		printf("Press any key to continue...");
		scanf("%c%c", &tmp);
	
	return 0;
}