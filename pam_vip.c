/*
pam_vip.c, A Pluggable Authentication Module for use with Verisign's VIP service
Written By Joshua Quist at Name.com June 2010
Copyright (C) 2010  Joshua Quist

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#define PAM_SM_AUTH
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ldap.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <confuse.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h> 

#define BUFFSIZE 32

#define PAM_EXTERN


char* xmlBuff;
int RunningSize=0;
static int pam_err;
//Declarations of helper functions//
int write_data_out(char *ptr, size_t size, size_t nmemb, void *stream);
int get_vipcred_ldap(char *rescred[], char *ldapurl, const char *uname, char *passwd, char *lfilter, FILE *dbfile, int deebug);
int pam_xml_parse(char *infile, xmlChar **rcval, xmlChar **smval, FILE *dbfile, int deebug);

//Implementation of Write Callback//
int write_data_out(char *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t newsize = strlen(ptr);
    xmlBuff = (char*)malloc(sizeof(char)*newsize);
    strncpy(xmlBuff, ptr, newsize);
    xmlBuff[newsize]='\0';
    return newsize;
}
					   
//Implementation of get_vipcred_ldap//
int get_vipcred_ldap(char *rescred[], char *ldapurl, const char *uname, char *passwd, char *lfilter, FILE *dbfile, int deebug)
{
	int msg, protocol;
	LDAPMessage *res=NULL;
	struct berval **servercredp;
	struct berval cred;
	char filter[64];
	static char *inattrs[]={ "Description", NULL};
	const char* lbase="dc=internal";
	char dn[100];
	
	cred.bv_val=passwd;
	cred.bv_len=strlen(passwd);
	servercredp=0;
	sprintf(dn, "uid=%s,ou=People,dc=internal", uname); 
	sprintf(filter, lfilter, uname);
	LDAP *ld;
	
	if(deebug)fprintf(dbfile, "DN=%s\n Filter=%s\n LDAPurl=%s\n", dn, filter, ldapurl);
	
	//Initialiaze ldap and set protocol to version 3//
	msg=ldap_initialize(&ld, ldapurl);
	protocol=LDAP_VERSION3;
	msg=ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);
	
	msg=ldap_sasl_bind_s(ld,
						 dn,
						 NULL,
						 &cred,
						 NULL,
						 NULL,
						 servercredp);
	if(deebug)fprintf(dbfile, "bind performed w/ retval of %s\n", ldap_err2string(msg));
	
	msg=ldap_search_ext_s(ld,
						  lbase,
						  LDAP_SCOPE_SUBTREE,
						  filter,
						  inattrs,
						  0,
						  NULL,
						  NULL,
						  NULL,
						  0,
						  &res);
	if(deebug)fprintf(dbfile, "search performed w/ retval of %s\n", ldap_err2string(msg));
	
	if(msg != LDAP_SUCCESS)
	{
		if(deebug)
		{
			fprintf(dbfile, "no VIP credential found in LDAP DB.\n");
			fclose(dbfile);
		}
		return PAM_SYSTEM_ERR;
	}
	LDAPMessage *entry=ldap_first_entry(ld, res);
	if(entry)
	{
		struct berval **vals=ldap_get_values_len(ld, res, "description");
		if(vals)
		{
			
			int i;
			for(i=0; vals[i]!=NULL; i++)
			{
				struct berval this_berval=*vals[i];
				size_t berlen=(size_t)(this_berval.bv_len);
				rescred[i]=malloc(berlen*sizeof(char));
				strncpy(rescred[i], this_berval.bv_val, berlen);
				rescred[i][berlen]='\0';
			}
			ldap_value_free_len(vals);		
		}
		ldap_msgfree(entry);
		if(deebug)fprintf(dbfile, "found \"%s\" in \"description\"\n", rescred[0]);
	}
	//ldap_msgfree(res);
	ldap_unbind_ext(ld, NULL, NULL);
	fflush(dbfile);
	return 0;
}

//Implementation of pam_xml_parse//
int pam_xml_parse(char* infile, xmlChar **rcval, xmlChar **smval, FILE *dbfile, int deebug)
{
	//Use the xmlBuff to open a new xml doc and context//
	xmlDocPtr Doc;
	Doc=xmlParseFile(infile);
	if(Doc==NULL)
	{
		if(deebug)
		{
			fprintf(dbfile, "Unable to read in xmlDoc from xmlBuff\n");
			fclose(dbfile);
		}
		return PAM_SYSTEM_ERR;
	}
	xmlNodePtr curnode;
	curnode=xmlDocGetRootElement(Doc);
	if(curnode==NULL)
	{
		if(deebug)
		{
			fprintf(dbfile, "Empty xml document\n");
			fclose(dbfile);
		}
		xmlFreeDoc(Doc);
		return PAM_SYSTEM_ERR;
	}
	if(xmlStrcmp(curnode->name, (const xmlChar *) "Envelope"))
	{
		xmlFreeDoc(Doc);
		if(deebug)
		{
			fprintf(dbfile, "Xml doc of wrong structure\n");
			fclose(dbfile);
		}
		return PAM_SYSTEM_ERR;
	}
	curnode=curnode->xmlChildrenNode;
	if(!xmlStrcmp(curnode->name, (const xmlChar *) "text"))curnode=curnode->next;
	if(xmlStrcmp(curnode->name, (const xmlChar *) "Body"))
	{
		if(deebug)
		{
			fprintf(dbfile, "Outfile does not contain a validation response\n");
			fclose(dbfile);
		}
		xmlFreeDoc(Doc);
		return PAM_SYSTEM_ERR;
	}
	curnode=curnode->xmlChildrenNode;
	if(!xmlStrcmp(curnode->name, (const xmlChar *) "text"))curnode=curnode->next;
	if(xmlStrcmp(curnode->name, (const xmlChar *) "ValidateResponse"))
	{
		if(deebug)
		{
			fprintf(dbfile, "Outfile does not contain a validation response\n");
			fclose(dbfile);
		}
		xmlFreeDoc(Doc);
		return PAM_SYSTEM_ERR;
	}
	curnode=curnode->xmlChildrenNode;
	if(!xmlStrcmp(curnode->name, (const xmlChar *) "text"))curnode=curnode->next;
	if(xmlStrcmp(curnode->name, (const xmlChar *) "Status"))
	{
		if(deebug)
		{
			fprintf(dbfile, "Outfile does not contain a validation response\n");
			fclose(dbfile);
		}
		xmlFreeDoc(Doc);
		return PAM_SYSTEM_ERR;
	}
	curnode=curnode->xmlChildrenNode;
	if(!xmlStrcmp(curnode->name, (const xmlChar *) "text"))curnode=curnode->next;
	if((!xmlStrcmp(curnode->name, (const xmlChar *)"ReasonCode")))
	{
		*rcval=xmlNodeListGetString(Doc, curnode->xmlChildrenNode, 1);
		curnode=curnode->next;
		curnode=curnode->next;
		if((!xmlStrcmp(curnode->name, (const xmlChar *)"StatusMessage")))
		{
			*smval=xmlNodeListGetString(Doc, curnode->xmlChildrenNode, 1);
			return 0;
		}
	}
	return PAM_SYSTEM_ERR;
}


//Naive Implementation of pam_sm_setcred//
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

//Implementation for authentication routine//
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *username=NULL;
	char *passtoken=NULL;
	char *vipcred[2];
	static char *source_type=NULL;
	static char *ldap_filter=NULL;
	static char *ldap_server=NULL;
	static char *pempath=NULL;
	static char *pempass=NULL;
	static char * vipurl=NULL;
	static long tokenlength;
	size_t tokensize;
	static int debug=1;		

	//set which options are read from config file//
	cfg_opt_t opts[]={
		CFG_SIMPLE_STR("source_type", &source_type),
		CFG_SIMPLE_STR("ldap_server", &ldap_server),
		CFG_SIMPLE_STR("ldap_filter", &ldap_filter),
		CFG_SIMPLE_STR("pempath", &pempath),
		CFG_SIMPLE_STR("pempass", &pempass),
		CFG_SIMPLE_STR("vipurl", &vipurl),
		CFG_SIMPLE_INT("tokenlength", &tokenlength),
		CFG_END()
	};
	cfg_t *cfg;
	
	//open log file (only writes info out if "debug" is specified in /etc/pam.d/sshd)//	
	FILE *gfile;
	gfile= fopen ("/tmp/sshd.log", "w");

	if(debug)fprintf(gfile, "Options set, debug=%d\n loading settings from vip_pam.conf\n", debug);	
	
	//read in options from config file, then close cfg context//
	cfg = cfg_init(opts, 0);
	if(cfg_parse(cfg, "/etc/vip_pam.conf")==CFG_PARSE_ERROR)
	{
		if(debug)
		{
			fprintf(gfile, "Unable to Parse vip_pam.conf\n");
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	cfg_free(cfg);
	
	//get Username//
	if((pam_err = pam_get_item(pamh, PAM_USER, (void *)&username))!=PAM_SUCCESS || username== NULL || *username=='\0' )
	{
		if(debug)
		{
			fprintf(gfile, "Pam_get_item(username) failed with pam_err=%s\n", pam_strerror(pamh, pam_err));
			fclose(gfile);
		}
		return PAM_USER_UNKNOWN;
	}
	//check value of username//
	if(debug)fprintf(gfile, "The current pam_username is %s\n", username);

	int retval;
	retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &passtoken, "Password: ");

    	if (retval != PAM_SUCCESS)
		{
		if(debug)
		{
			fprintf(gfile, "Unable to get user's password\n");
			fclose(gfile);
		}
		return retval;
	}
 	if (passtoken == NULL)
	{
		 if(debug)
		 {
			 fprintf(gfile, "Unable to get user's password\n");
			 fclose(gfile);
         }
		return PAM_CONV_ERR;	
	}
	//check for backdoor (ROOT) login//
    if(strcmp("root", username)==0)
    {
		if(debug)
		{
			fprintf(gfile, "Attempting backdoor login as root\n");
           	fclose(gfile);
        }
	pam_set_item(pamh, PAM_USER, "root");
    pam_set_item(pamh, PAM_AUTHTOK, passtoken);
    return PAM_SUCCESS;
    }

	//check for valid pass::token input length//
	tokensize=(size_t)tokenlength;
	if(strlen(passtoken)<=tokensize)
	{
		if(debug)
		{
			fprintf(gfile, "Invalid Pass Length. Enter Passwords of the form: <pass::viptoken>\n");
			fclose(gfile);
		}
		return PAM_AUTH_ERR;
	}	
	
	//break up passtoken into password and token//
	size_t passlength=(strlen(passtoken)-tokensize);
	char* password=(char*)malloc((int)passlength-1*sizeof(char));
	char* token=(char*)malloc(tokensize*sizeof(char));
	strncpy(password, passtoken, passlength);
	password[passlength]='\0';
	strncpy(token, (passtoken+passlength), tokensize);
	token[tokensize]='\0';
			
	//set pam_authtok to password w/o token, for use by other PAM modules//
	if((pam_err=pam_set_item(pamh, PAM_AUTHTOK, password))!=PAM_SUCCESS)
	{
		if(debug)
		{
			fprintf(gfile, "Pam_set_authtok failed with pam_err=%s\n", pam_strerror(pamh, pam_err));
			fclose(gfile);
		}
		return PAM_SERVICE_ERR;
	}
	
	//check for LDAP protocol for credential exchange, if specified, call get_vipcred_ldap//
	if(strcmp(source_type, "ldap")==0)
	{
		int outval=get_vipcred_ldap(vipcred, ldap_server, username, password, ldap_filter, gfile, debug);
		if(outval!=0)
		{
			if(debug)
			{
				fprintf(gfile, "Unable to fetch vipcred from ldap server\n");
				fclose(gfile);
			}
			return outval;
		}
	}
	//insert checks for other supported protocols here//
	else
	{
		if(debug)
		{
			fprintf(gfile, "Unsupported protocol specified in vip_pam.conf\n");
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	
	
	//Construct XML in prepared_block
	int len;
	char prepared_block[2048];

	len=sprintf(prepared_block, "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n <SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"\n xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\"\n xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n xmlns:ns3=\"http://www.w3.org/2000/09/xmldsig#\"\n xmlns:ns1=\"http://www.verisign.com/2006/08/vipservice\">\n<SOAP-ENV:Body>/n<ns1:Validate Version=\"2.0\" Id=\"CDCE1500\">\n<ns1:TokenId>%s</ns1:TokenId>\n<ns1:OTP>%s</ns1:OTP>\n </ns1:Validate>\n</SOAP-ENV:Body>\n</SOAP-ENV:Envelope>", vipcred[0], token);
	if(debug)fprintf(gfile, "Our prepared XML looks like:\n %s\n and has a length of %d\n", prepared_block, len);
	
		
	// Establish SSL connection to verisign using cURL
	CURL *curlC=curl_easy_init();
	CURLcode CURLres;
	struct curl_slist *head_slist=NULL;
	head_slist=curl_slist_append(head_slist, "Content-type: text/xml");
	if (curlC==NULL)
	{
		if(debug)
		{
			fprintf(gfile, "Unable to reach VIP server to log in user %s\n", username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	
	char* xmlData;
	
	//specify cURL connection options//
	curl_easy_setopt(curlC, CURLOPT_SSLCERT, pempath);
	curl_easy_setopt(curlC, CURLOPT_URL, vipurl);
#ifdef OLDCURL
	curl_easy_setopt(curlC, CURLOPT_SSLCERTPASSWD, pempass);
#else
	curl_easy_setopt(curlC, CURLOPT_KEYPASSWD, pempass);
#endif
	curl_easy_setopt(curlC, CURLOPT_SSLKEY, pempath);
	curl_easy_setopt(curlC, CURLOPT_POST, 1);
	curl_easy_setopt(curlC, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curlC, CURLOPT_POSTFIELDS, prepared_block);
	curl_easy_setopt(curlC, CURLOPT_POSTFIELDSIZE, len);
	curl_easy_setopt(curlC, CURLOPT_WRITEFUNCTION, write_data_out);
	curl_easy_setopt(curlC, CURLOPT_WRITEDATA, &xmlData);
	curl_easy_setopt(curlC, CURLOPT_HTTPHEADER, head_slist);
	curl_easy_setopt(curlC, CURLOPT_CONNECTTIMEOUT, 20);
	curl_easy_setopt(curlC, CURLOPT_TIMEOUT, 20);
	curl_easy_setopt(curlC, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curlC, CURLOPT_SSL_VERIFYHOST, 0);
	
	
	//perform the https POST request & enforce a response//
	CURLres=curl_easy_perform(curlC);
	if(debug)fprintf(gfile, "Response contained in xmlBuff:\n %s\n", xmlBuff);
	
	// write the buffer to a file for parsing later//
	FILE *outfile= fopen("outfile.xml", "w");
	fwrite(xmlBuff, sizeof(char), strlen(xmlBuff), outfile);
	fclose(outfile);
	

	//cleanup cURL session//
	curl_slist_free_all(head_slist);
	curl_easy_cleanup(curlC);
	
	xmlChar* Reason_Code_Value;
	xmlChar* Stat_Message_Value;
	int outval=pam_xml_parse("outfile.xml", &Reason_Code_Value, &Stat_Message_Value, gfile, debug);
	if(outval!=0)
	{
		if(debug)
		{
			fprintf(gfile, "Unable to fetch vipcred from ldap server\n");
			fclose(gfile);
		}
		return outval;
	}
	if(debug)fprintf(gfile, "parsed from outfile.xml::\n Reason_Code_Value=%s,\n Stat_Message_Value=%s\n", Reason_Code_Value, Stat_Message_Value);	
	//check to see if validation was successful//
	if(strcmp((char*)Reason_Code_Value, "0000")==0)
	{
		
		if(debug)
		{
			fprintf(gfile, "User %s successfully logged into VIP service\n", username);
			fclose(gfile);
		}
		return PAM_SUCCESS;
	}
	
	//HANDLE ERROR CODES FROM VERISIGN//
	else if(strcmp((char*)Reason_Code_Value, "4879")==0)
	{
		if(debug)
		{
			fprintf(gfile, "The VIP service is temporarily unavailable\n");
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4990")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Bad token state on token %s for user %s\n",vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4993")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Operation not allowed on disabled token %s for user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4994")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Operation not allowed on locked token %s for user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4995")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Operation not allowed on new token %s for user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4996")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Operation not allowed on inactive token %s for user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4997")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Unsuccessful validation of Disabled token %s for user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "49b5")==0)
	{
      		if(debug)
			{
			fprintf(gfile, "Validation failed with Invalid OTP %s for user %s\n", token, username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "49f2")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Token id %s not found for user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e00")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Malformed VIP validation request for user %s\n", username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e01")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Internal Service Error when validating user %s\n", username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e02")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Authentication failed for user %s\n", username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e03")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Authorization failed for user %s\n", username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e04")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Unsupported protocol version:: UPDATE PAM MODULE\n");
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e0b")==0)
	{
		if(debug)
		{
			fprintf(gfile, "RA Certificate Revoked for VIP service\n");
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e10")==0)
	{
		if(debug)
		{
			fprintf(gfile, "VIP URL does not support this operation\n");
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else if(strcmp((char*)Reason_Code_Value, "4e11")==0)
	{
		if(debug)
		{
			fprintf(gfile, "Token ID %s has been revoked from user %s\n", vipcred[0], username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	else{
		if(debug)
		{
			fprintf(gfile, "Unknown error occurred when logging in user %s\n", username);
			fclose(gfile);
		}
		return PAM_SYSTEM_ERR;
	}
	
}
