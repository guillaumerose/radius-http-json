/*
 * rlm_remotedb.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2010 Guillaume Rose <guillaume.rose@gmail.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/sysutmp.h>

#include <json/json.h>
#include <curl/curl.h>

typedef struct rlm_remotedb_t {
	char	*ip;
	int	port;
	char	*base;
} rlm_remotedb_t;

static const CONF_PARSER module_config[] = {
  { "port", PW_TYPE_INTEGER,    offsetof(rlm_remotedb_t, port), NULL,   "80" },
  { "ip",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t, ip), NULL,  "127.0.0.1"},
  { "base",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t, base), NULL,  ""},
  
  { NULL, -1, 0, NULL, NULL }
};

static int remotedb_disable = 0;

static int
get_timestamp()
{
	time_t timestamp;
	time(&timestamp);
	return (int) timestamp;
}

static int 
remotedb_instantiate(CONF_SECTION *conf, void **instance)
{
        rlm_remotedb_t *data;
        
        data = rad_malloc(sizeof(*data));
        if (!data) {
             return -1;
        }
        memset(data, 0, sizeof(*data));
        
        if (cf_section_parse(conf, data, module_config) < 0) {
             free(data);
             return -1;
        }
        
        *instance = data;

	return 0;
}

static int
remotedb_answer_builder(REQUEST *request, const char *password, const char *vlan)
{
        VALUE_PAIR *pair;

        radlog(L_DBG, "Building answer : password = %s, vlan = %s\n", password, vlan);

        pair = pairmake("NT-Password", password, T_OP_SET);	
        pairmove(&request->config_items, &pair);
        pairfree(&pair);

        pair = pairmake("Tunnel-Private-Group-Id", vlan, T_OP_SET);
        pairadd(&request->reply->vps, pair);
        
        pair = pairmake("Tunnel-Medium-Type", "6", T_OP_SET);
        pairadd(&request->reply->vps, pair);
        
        pair = pairmake("Tunnel-Type", "13", T_OP_SET);
        pairadd(&request->reply->vps, pair);
        
        return RLM_MODULE_OK;
}

static size_t 
remotedb_curl( void *ptr, size_t size, size_t nmemb, void *userdata)
{
        REQUEST *request = (REQUEST *) userdata;
		
	json_object * jobj = json_tokener_parse(ptr);
	
	if ((int) jobj < 0) {
                printf("Invalid json\n");
		return nmemb * size;
	}

	struct json_object *jvlan;
	struct json_object *jpassword;
	
	if (json_object_get_type(jobj) != json_type_object) {
		printf("Wrong type in field\n");
		return 0;
	}
	
	if ((jvlan = json_object_object_get(jobj, "vlan")) == NULL) {
		printf("vlan field needed\n");
		return 0;
	}

	if ((jpassword = json_object_object_get(jobj, "password")) == NULL) {
		printf("password field needed\n");
		return 0;
	}

        remotedb_answer_builder(request, json_object_get_string(jpassword), json_object_get_string(jvlan));
        
	json_object_put(jobj);
	
	return nmemb * size;
}

static int 
remotedb_authorize(void *instance, REQUEST *request)
{
        if (remotedb_disable && get_timestamp() - remotedb_disable <= 30)
                return RLM_MODULE_FAIL;
        
        if (request->username == NULL)
                return RLM_MODULE_NOOP;
	
        rlm_remotedb_t *data = (rlm_remotedb_t *) instance;

        char mac[1024] = "";
	char uri[1024] = "";

        radius_xlat(mac, 1024, "%{Calling-Station-Id}", request, NULL);
                
        radlog(L_DBG, "Search with following options : mac address = %s, username = %s\n", mac, request->username->vp_strvalue);
        
	sprintf(uri, "http://%s:%d%s/authenticate?login=%s&mac=%s", data->ip, data->port, data->base, request->username->vp_strvalue, mac);
        
        radlog(L_DBG, "Calling %s\n", uri);
	
	CURL *curl;
	CURLcode res = CURLE_FAILED_INIT;
	
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, uri);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, remotedb_curl);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, request);
		
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1);
		
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	if (res != CURLE_OK) {
	        remotedb_disable = get_timestamp();
                radlog(L_ERR, "Failed to call %s, retry in few seconds\n", uri);
		return RLM_MODULE_FAIL;
	}

        return RLM_MODULE_OK;
}

static int 
remotedb_accounting(void *instance, REQUEST *request)
{
	VALUE_PAIR	*vp;
	time_t		t;
	char buf[80];
	struct tm  *ts;
	
	if (request->packet->src_ipaddr.af != AF_INET) {
		RDEBUG2("IPv6 is not supported!");
		return RLM_MODULE_NOOP;
	}

	if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE))==NULL) {
		radlog(L_ERR, "rlm_remotedb: no Accounting-Status-Type attribute in request.");
		return RLM_MODULE_NOOP;
	}
	
	printf("STATUS = %d\n", vp->vp_integer);


	if (pairfind(request->packet->vps, PW_USER_NAME) == NULL)
		return RLM_MODULE_NOOP;

	t = request->timestamp;

        ts = localtime(&t);
        strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", ts);

	printf("TIMESTAMP = %s\n", buf);
        
	for (vp = request->packet->vps; vp; vp = vp->next) {
		switch (vp->attribute) {
			case PW_NAS_PORT_ID_STRING:
		        case PW_ACCT_SESSION_ID:
			case PW_USER_NAME:
				printf("DATA = %s\n", (char *)vp->vp_strvalue);
				break;
		}
	}

	return RLM_MODULE_OK;
}

static int 
remotedb_detach(void *instance)
{
	free(instance);
	return 0;
}

module_t rlm_remotedb = {
	RLM_MODULE_INIT,
	"remotedb",
	RLM_TYPE_THREAD_SAFE,		/* type */
	remotedb_instantiate,		/* instantiation */
	remotedb_detach,		/* detach */
	{
		NULL,                   /* authentication */
		remotedb_authorize,	/* authorization */
		NULL,			/* preaccounting */
		remotedb_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
