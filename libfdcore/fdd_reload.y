/*********************************************************************************************************
* Software License Agreement (BSD License)                                                               *
* Author: Sebastien Decugis <sdecugis@freediameter.net>							 *
*													 *
* Copyright (c) 2019, WIDE Project and NICT								 *
* All rights reserved.											 *
* 													 *
* Redistribution and use of this software in source and binary forms, with or without modification, are  *
* permitted provided that the following conditions are met:						 *
* 													 *
* * Redistributions of source code must retain the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer.										 *
*    													 *
* * Redistributions in binary form must reproduce the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer in the documentation and/or other						 *
*   materials provided with the distribution.								 *
* 													 *
* * Neither the name of the WIDE Project or NICT nor the 						 *
*   names of its contributors may be used to endorse or 						 *
*   promote products derived from this software without 						 *
*   specific prior written permission of WIDE Project and 						 *
*   NICT.												 *
* 													 *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED *
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR *
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 	 *
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 	 *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR *
* TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF   *
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.								 *
*********************************************************************************************************/

/* Yacc configuration parser.
 *
 * This file defines the grammar of the configuration file.
 * Note that each extension has a separate independant configuration file.
 *
 * Note : This module is NOT thread-safe. All processing must be done from one thread only.
 */

/* For development only : */
%debug 
%error-verbose

%parse-param {struct fd_config * conf}

/* Keep track of location */
%locations 
%pure-parser

%{
#include "fdcore-internal.h"
#include "fdd.tab.h"	/* bug : bison does not define the YYLTYPE before including this bloc, so... */

/* The Lex parser prototype */
int fddlex(YYSTYPE *lvalp, YYLTYPE *llocp);

#define fdd_reloadlex fddlex

/* Function to report error */
void fdd_reloaderror (YYLTYPE *ploc, struct fd_config * conf, char const *s)
{
	if (ploc->first_line != ploc->last_line) {
		TRACE_ERROR("%s:%d.%d-%d.%d : %s", conf->cnf_file, ploc->first_line, ploc->first_column, ploc->last_line, ploc->last_column, s);
	} else if (ploc->first_column != ploc->last_column) {
		TRACE_ERROR("%s:%d.%d-%d : %s", conf->cnf_file, ploc->first_line, ploc->first_column, ploc->last_column, s);
	} else {
		TRACE_ERROR("%s:%d.%d : %s", conf->cnf_file, ploc->first_line, ploc->first_column, s);
	}
}

int got_peer_noip_reload = 0;
int got_peer_noipv6_reload = 0;
int got_peer_notcp_reload = 0;
int got_peer_nosctp_reload = 0;

struct peer_info fddpi_reload;

%}

/* Values returned by lex for token */
%union {
	char 		 *string;	/* The string is allocated by strdup in lex.*/
	int		  integer;	/* Store integer values */
}

/* In case of error in the lexical analysis */
%token 		LEX_ERROR

%token <string>	QSTRING
%token <integer> INTEGER

%type <string> 	extconf

%token		IDENTITY
%token		REALM
%token		PORT
%token		SECPORT
%token		SEC3436
%token		NOIP
%token		NOIP6
%token		NOTCP
%token		NOSCTP
%token		PREFERTCP
%token		OLDTLS
%token		NOTLS
%token		SCTPSTREAMS
%token		APPSERVTHREADS
%token		ROUTINGINTHREADS
%token		ROUTINGOUTTHREADS
%token		QINLIMIT
%token		QOUTLIMIT
%token		QLOCALLIMIT
%token		LISTENON
%token		THRPERSRV
%token		PROCESSINGPEERSPATTERN
%token		PROCESSINGPEERSMINIMUM
%token		TCTIMER
%token		TWTIMER
%token		NORELAY
%token		LOADEXT
%token		CONNPEER
%token		CONNTO
%token		PEERTYPE
%token		CERHOSTIPWHITELIST
%token		TLS_CRED
%token		TLS_CA
%token		TLS_CRL
%token		TLS_PRIO
%token		TLS_DH_BITS
%token		TLS_DH_FILE
%token		RR_IN_ANSWERS
%token		ALWAYS
%token		NEVER


/* -------------------------------------- */
%%

	/* The grammar definition - Sections blocs. */
conffile:		/* Empty is OK -- for simplicity here, we reject in daemon later */
			| conffile connpeer
			| conffile errors
			{
				yyerror(&yylloc, conf, "An error occurred while parsing the configuration file");
				return EINVAL;
			}
			;

			/* Lexical or syntax error */
errors:			LEX_ERROR
			| error
			;
connpeer:	{
				memset(&fddpi_reload, 0, sizeof(fddpi_reload));
				fddpi_reload.config.pic_flags.persist = PI_PRST_ALWAYS;
				fd_list_init( &fddpi_reload.pi_endpoints, NULL );
				fd_list_init( &fddpi_reload.cer_host_ip_whitelist, NULL );
			}
			CONNPEER '=' QSTRING peerinfo ';'
			{
				fddpi_reload.pi_diamid = $4;
				int ret = fd_peer_add ( &fddpi_reload, conf->cnf_file, NULL, NULL );
				if (ret != 0 && ret != EEXIST) {
					yyerror (&yylloc, conf, "Error adding ConnectPeer information"); YYERROR;
				}

				/* Now destroy any content in the structure */
				free(fddpi_reload.pi_diamid);
				free(fddpi_reload.config.pic_realm);
				free(fddpi_reload.config.pic_priority);
				while (!FD_IS_LIST_EMPTY(&fddpi_reload.pi_endpoints)) {
					struct fd_list * li = fddpi_reload.pi_endpoints.next;
					fd_list_unlink(li);
					free(li);
				}
				while (!FD_IS_LIST_EMPTY(&fddpi_reload.cer_host_ip_whitelist)) {
					struct fd_list * li = fddpi_reload.cer_host_ip_whitelist.next;
					fd_list_unlink(li);
					free(li);
				}
			}
			;
			
peerinfo:		/* empty */
			| '{' peerparams '}'
			;
			
peerparams:		/* empty */
			| peerparams NOIP ';'
			{
				if ((conf->cnf_flags.no_ip6) || (fddpi_reload.config.pic_flags.pro3 == PI_P3_IP)) { 
					yyerror (&yylloc, conf, "No_IP conflicts with a No_IPv6 directive.");
					YYERROR;
				}
				got_peer_noip_reload++;
				fddpi_reload.config.pic_flags.pro3 = PI_P3_IPv6;
			}
			| peerparams NOIP6 ';'
			{
				if ((conf->cnf_flags.no_ip4) || (fddpi_reload.config.pic_flags.pro3 == PI_P3_IPv6)) { 
					yyerror (&yylloc, conf, "No_IPv6 conflicts with a No_IP directive.");
					YYERROR;
				}
				got_peer_noipv6_reload++;
				fddpi_reload.config.pic_flags.pro3 = PI_P3_IP;
			}
			| peerparams NOTCP ';'
			{
				#ifdef DISABLE_SCTP
					yyerror (&yylloc, conf, "No_TCP cannot be specified in daemon compiled with DISABLE_SCTP option.");
					YYERROR;
				#endif
				if ((conf->cnf_flags.no_sctp) || (fddpi_reload.config.pic_flags.pro4 == PI_P4_TCP)) { 
					yyerror (&yylloc, conf, "No_TCP conflicts with a No_SCTP directive.");
					YYERROR;
				}
				got_peer_notcp_reload++;
				fddpi_reload.config.pic_flags.pro4 = PI_P4_SCTP;
			}
			| peerparams NOSCTP ';'
			{
				if ((conf->cnf_flags.no_tcp) || (fddpi_reload.config.pic_flags.pro4 == PI_P4_SCTP)) { 
					yyerror (&yylloc, conf, "No_SCTP conflicts with a No_TCP directive.");
					YYERROR;
				}
				got_peer_nosctp_reload++;
				fddpi_reload.config.pic_flags.pro4 = PI_P4_TCP;
			}
			| peerparams PREFERTCP ';'
			{
				fddpi_reload.config.pic_flags.alg = PI_ALGPREF_TCP;
			}
			| peerparams OLDTLS ';'
			{
				fddpi_reload.config.pic_flags.sec |= PI_SEC_TLS_OLD;
			}
			| peerparams NOTLS ';'
			{
				fddpi_reload.config.pic_flags.sec |= PI_SEC_NONE;
			}
			| peerparams SEC3436 ';'
			{
				fddpi_reload.config.pic_flags.sctpsec |= PI_SCTPSEC_3436;
			}
			| peerparams REALM '=' QSTRING ';'
			{
				fddpi_reload.config.pic_realm = $4;
			}
			| peerparams PORT '=' INTEGER ';'
			{
				CHECK_PARAMS_DO( ($4 > 0) && ($4 < 1<<16),
					{ yyerror (&yylloc, conf, "Invalid port value"); YYERROR; } );
				fddpi_reload.config.pic_port = (uint16_t)$4;
			}
			| peerparams TCTIMER '=' INTEGER ';'
			{
				fddpi_reload.config.pic_tctimer = $4;
			}
			| peerparams TWTIMER '=' INTEGER ';'
			{
				fddpi_reload.config.pic_twtimer = $4;
			}
			| peerparams TLS_PRIO '=' QSTRING ';'
			{
				fddpi_reload.config.pic_priority = $4;
			}
			| peerparams CONNTO '=' QSTRING ';'
			{
				struct addrinfo hints, *ai;
				int ret;
				int disc = 0;
				
				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST;
				ret = getaddrinfo($4, NULL, &hints, &ai);
				if (ret == EAI_NONAME) {
					/* The name was maybe not numeric, try again */
					disc = EP_FL_DISC;
					hints.ai_flags &= ~ AI_NUMERICHOST;
					ret = getaddrinfo($4, NULL, &hints, &ai);
				}
				if (ret) { yyerror (&yylloc, conf, gai_strerror(ret)); YYERROR; }
				
				CHECK_FCT_DO( fd_ep_add_merge( &fddpi_reload.pi_endpoints, ai->ai_addr, ai->ai_addrlen, EP_FL_CONF | (disc ?: EP_ACCEPTALL) ), YYERROR );
				free($4);
				freeaddrinfo(ai);
			}
			| peerparams CERHOSTIPWHITELIST '=' QSTRING ';'
			{
				struct addrinfo hints, *ai;
				int ret;
				int disc = 0;

				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST;
				ret = getaddrinfo($4, NULL, &hints, &ai);
				if (ret == EAI_NONAME) {
					/* The name was maybe not numeric, try again */
					disc = EP_FL_DISC;
					hints.ai_flags &= ~ AI_NUMERICHOST;
					ret = getaddrinfo($4, NULL, &hints, &ai);
				}
				if (ret) { yyerror (&yylloc, conf, gai_strerror(ret)); YYERROR; }
				
				CHECK_FCT_DO( fd_ep_add_merge( &fddpi_reload.cer_host_ip_whitelist, ai->ai_addr, ai->ai_addrlen, EP_FL_CONF | (disc ?: EP_ACCEPTALL) ), YYERROR );
				free($4);
				freeaddrinfo(ai);
			}
			| peerparams PEERTYPE '=' QSTRING ';'
			{
				if ((0 == strcmp("client", $4)) ||
				    (0 == strcmp("Client", $4)))
				{
					fddpi_reload.config.cnf_peer_type_client = 1;
				} else {
					fddpi_reload.config.cnf_peer_type_client = 0;
				}
			}
			;

