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

typedef struct rlm_remotedb_t {
	char	*ip;
	int	port;
} rlm_remotedb_t;


static const CONF_PARSER module_config[] = {
  { "port", PW_TYPE_INTEGER,    offsetof(rlm_remotedb_t,port), NULL,   "27017" },
  { "ip",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,ip), NULL,  "127.0.0.1"},
  // 
  // { "base",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,base), NULL,  ""},
  // { "search_field",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,search_field), NULL,  ""},
  // { "username_field",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,username_field), NULL,  ""},
  // { "password_field",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,password_field), NULL,  ""},
  // { "mac_field",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,mac_field), NULL,  ""},
  // { "enable_field",  PW_TYPE_STRING_PTR, offsetof(rlm_remotedb_t,enable_field), NULL,  ""},
  
  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

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

// static void 
// format_mac(char *in, char *out) 
// {
//      int i;
//      for (i = 0; i < 6; i++) {
//              out[3 * i] = in[2 * i];
//              out[3 * i + 1] = in[2 * i + 1];
//              out[3 * i + 2] = ':';
//      }
//      out[17] = '\0';
// }

static int 
remotedb_authorize(void *instance, REQUEST *request)
{
        if (request->username == NULL)
                return RLM_MODULE_NOOP;
	
        rlm_remotedb_t *data = (rlm_remotedb_t *) instance;
	
        char password[1024] = "toto";
        char mac[1024] = "";

        // char mac_temp[1024] = "";
        radius_xlat(mac, 1024, "%{Calling-Station-Id}", request, NULL);
        // format_mac(mac_temp, mac);

        printf("\nMac addr -> \"%s\"\n", mac);
        printf("\nAutorisation request by username -> \"%s\"\n", request->username->vp_strvalue);
        printf("Password found in MongoDB -> \"%s\"\n\n", password);

        VALUE_PAIR *vp;

        /* quiet the compiler */
        instance = instance;
        request = request;

        // Unsecure : Cleartext-Password
        vp = pairmake("NT-Password", "fbbf55d0ef0e34d39593f55c5f2ca5f2", T_OP_SET);
        if (!vp) 
                return RLM_MODULE_FAIL;
	
        pairmove(&request->config_items, &vp);
        pairfree(&vp);
        
        VALUE_PAIR *timeout;
        
        timeout = pairmake("Tunnel-Private-Group-Id", "41", T_OP_SET);
        pairadd(&request->reply->vps, timeout);
        timeout = pairmake("Tunnel-Medium-Type", "6", T_OP_SET);
        pairadd(&request->reply->vps, timeout);
        timeout = pairmake("Tunnel-Type", "13", T_OP_SET);
        pairadd(&request->reply->vps, timeout);
        
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
		remotedb_authorize,     /* authentication */
		remotedb_authorize,	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};


