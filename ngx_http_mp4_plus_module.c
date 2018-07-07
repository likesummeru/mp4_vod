/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc
 * Copyright (C) zhaojunsong.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_slice_plus.h"
#include "ngx_http_mp4_process.h"

#define NGX_HTTP_MP4_PLUS_DEFAULT_BUFFER_SIZE    512 * 1024
#define NGX_HTTP_MP4_PLUS_DEFAULT_MAX_BUFFER_SIZE    1024 * 1024

#define NGX_HTTP_MP4_PLUS_SEEK_TYPE_TIME   0
#define NGX_HTTP_MP4_PLUS_SEEK_TYPE_BYTES  1

extern ngx_module_t ngx_http_slice_plus_filter_module;


typedef struct {
	ngx_variable_value_t *seek_type;
	ngx_variable_value_t *seek_start;       
	ngx_variable_value_t *seek_end;       
	ngx_variable_value_t *seek_up;       
	ngx_variable_value_t *seek_preview;
	ngx_variable_value_t *seek_return_type;//unused
}ngx_http_mp4_plus_var_t;

typedef struct {
	u_char* ftyp;
	size_t ftyp_size;
	u_char* moov;
	size_t moov_size;
	u_char   mdat_head[16];
}ngx_http_mp4_plus_check_metadata_ctx_t;

typedef struct {
	off_t seek_start;
	off_t seek_end;
	off_t seek_preview;
	ngx_int_t seek_type;
	ngx_int_t seek_up;
	
	ngx_http_mp4_plus_var_t var;
	ngx_http_mp4_plus_check_metadata_ctx_t metadata;

}ngx_http_mp4_plus_ctx_t;


typedef struct {
   ngx_flag_t seek_keyframe; //unused
} ngx_http_mp4_plus_conf_t;

static char *
ngx_http_mp4_plus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_mp4_plus_preconfiguration(ngx_conf_t *cf);
static ngx_int_t 
ngx_http_mp4_plus_get_mod (ngx_http_request_t* r);
static ngx_int_t 
ngx_http_mp4_plus_process_metadata(ngx_http_request_t* r , ngx_buf_t* metadata, ngx_http_slice_plus_metadata_t **result);
static ngx_int_t 
ngx_http_mp4_plus_process_metadata_use_time_seek(ngx_http_request_t* r , ngx_buf_t* metadata, ngx_http_slice_plus_metadata_t **result);
static ngx_int_t 
ngx_http_mp4_plus_get_number_var(ngx_variable_value_t* var, off_t *number);
static ngx_int_t
ngx_http_mp4_parse_variable(ngx_http_request_t *r);
static ngx_int_t 
ngx_http_mp4_plus_check_metadata(ngx_http_request_t* r , ngx_buf_t* metadata);
static ngx_int_t
ngx_http_mp4_plus_read_atom(ngx_http_mp4_plus_ctx_t *ctx, ngx_buf_t* metadata);
static void 
ngx_http_mp4_plus_get_seek_time(ngx_http_mp4_plus_ctx_t *ctx, ngx_uint_t *seek_start, ngx_uint_t *seek_end, ngx_uint_t *seek_length);
static void *ngx_http_mp4_plus_create_conf(ngx_conf_t *cf);
static char *
ngx_http_mp4_plus_merge_conf(ngx_conf_t *cf, void *parent, void *child);


#define ngx_mp4_plus_get_32value(p)                                  \
    ( ((uint32_t) ((u_char *) (p))[0] << 24)                                  \
    + (           ((u_char *) (p))[1] << 16)                                     \
    + (           ((u_char *) (p))[2] << 8)                                       \
    + (           ((u_char *) (p))[3]) )


#define ngx_mp4_plus_get_64value(p)                                  \
    ( ((uint64_t) ((u_char *) (p))[0] << 56)                                  \
    + ((uint64_t) ((u_char *) (p))[1] << 48)                                  \
    + ((uint64_t) ((u_char *) (p))[2] << 40)                                  \
    + ((uint64_t) ((u_char *) (p))[3] << 32)                                  \
    + ((uint64_t) ((u_char *) (p))[4] << 24)                                  \
    + (           ((u_char *) (p))[5] << 16)                                      \
    + (           ((u_char *) (p))[6] << 8)                                        \
    + (           ((u_char *) (p))[7]) )

	


static ngx_http_module_t  ngx_http_mp4_plus_module_ctx = {
    ngx_http_mp4_plus_preconfiguration,          /* preconfiguration */
    NULL,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,        /* create location configuration */
    NULL          /* merge location configuration */
};

static ngx_command_t  ngx_http_mp4_plus_commands[] = {

    { ngx_string("mp4_plus"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_mp4_plus,
      0,
      0,
      NULL },

    { ngx_string("seek_keyframe"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mp4_plus_conf_t, seek_keyframe),
      NULL },

      ngx_null_command
};


ngx_module_t  ngx_http_mp4_plus_module = {
    NGX_MODULE_V1,
    &ngx_http_mp4_plus_module_ctx,     /* module context */
    ngx_http_mp4_plus_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_http_slice_plus_metadata_handler_t mp4_metadata_handler; 

#define NGX_HTTP_MP4_PLUS_VARIABLE_SET(name)                                                                                                             \
static void ngx_http_mp4_plus_variable_seek_##name##_set(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data){ \
       ngx_http_mp4_plus_ctx_t *ctx;                                                                                                                                              \
	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_plus_module);                                                                                 \
	if(!ctx){                                                                                                                                                                              \
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mp4_plus_ctx_t));                                                                                       \
		if(ctx == NULL)                                                                                                                                                             \
			return;                                                                                                                                                                 \
		ngx_http_set_ctx(r, ctx, ngx_http_mp4_plus_module);                                                                                           \
	}                                                                                                                                                                                        \
	ctx->var.seek_##name=v;                                                                                                                                                 \
}

#define NGX_HTTP_MP4_PLUS_VARIABLE_GET(name)                                                                                                            \
static ngx_int_t ngx_http_mp4_plus_variable_seek_##name(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data){   \
       ngx_http_mp4_plus_ctx_t *ctx;																				    \
	ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_plus_module);										                  \
	if(!ctx){ 																	                                                            \
		v->not_found = 1;																                                             \
	}										                                                                                                                    \
	else	{																                                                                   \
	      *v = *ctx->var.seek_##name;										                                                                   \
	}									                                                                                                                           \
	return NGX_OK;                                             														                         \
}

NGX_HTTP_MP4_PLUS_VARIABLE_SET(type)
NGX_HTTP_MP4_PLUS_VARIABLE_SET(start)
NGX_HTTP_MP4_PLUS_VARIABLE_SET(end)
NGX_HTTP_MP4_PLUS_VARIABLE_SET(up)
NGX_HTTP_MP4_PLUS_VARIABLE_SET(preview)
NGX_HTTP_MP4_PLUS_VARIABLE_SET(return_type)

NGX_HTTP_MP4_PLUS_VARIABLE_GET(type)
NGX_HTTP_MP4_PLUS_VARIABLE_GET(start)
NGX_HTTP_MP4_PLUS_VARIABLE_GET(end)
NGX_HTTP_MP4_PLUS_VARIABLE_GET(up)
NGX_HTTP_MP4_PLUS_VARIABLE_GET(preview)
NGX_HTTP_MP4_PLUS_VARIABLE_GET(return_type)

#undef NGX_HTTP_MP4_PLUS_VARIABLE_SET
#undef NGX_HTTP_MP4_PLUS_VARIABLE_GET


static ngx_http_variable_t ngx_http_mp4_plus_vars[] = {
	{ ngx_string("mp4_vod_seek_start"), 
		ngx_http_mp4_plus_variable_seek_start_set, 
		ngx_http_mp4_plus_variable_seek_start, 
		0, 
		NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 
		0 },
	{ ngx_string("mp4_vod_seek_end"), 
		ngx_http_mp4_plus_variable_seek_end_set, 
		ngx_http_mp4_plus_variable_seek_end, 
		0, 
		NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 
		0 },
	{ ngx_string("mp4_vod_seek_type"), 
		ngx_http_mp4_plus_variable_seek_type_set, 
		ngx_http_mp4_plus_variable_seek_type, 
		0, 
		NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 
		0 },
	{ ngx_string("mp4_vod_preview"), 
		ngx_http_mp4_plus_variable_seek_preview_set, 
		ngx_http_mp4_plus_variable_seek_preview, 
		0, 
		NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 
		0 },
	{ ngx_string("mp4_vod_seek_up"), 
		ngx_http_mp4_plus_variable_seek_up_set, 
		ngx_http_mp4_plus_variable_seek_up, 
		0, 
		NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 
		0 },
		
	{ ngx_string("mp4_vod_seek_return_type"), 
		ngx_http_mp4_plus_variable_seek_return_type_set,
		ngx_http_mp4_plus_variable_seek_return_type, 
		0, 
		NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 
		0 },

	{ ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static char *
ngx_http_mp4_plus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    if(metadata_handler)
    {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "slice_plus metadata handler is duplicate");
    }
	
    metadata_handler = &mp4_metadata_handler;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_mp4_plus_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_mp4_plus_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, 0);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->set_handler = v->set_handler;
		var->data = v->data;
		var->flags = v->flags;
    }

    mp4_metadata_handler.get_mod = ngx_http_mp4_plus_get_mod;
    mp4_metadata_handler.process_metatdata = ngx_http_mp4_plus_process_metadata;

    return NGX_OK;
}

static ngx_int_t 
ngx_http_mp4_plus_get_mod(ngx_http_request_t* r)
{
	ngx_int_t rc;
	rc = ngx_http_mp4_parse_variable(r);
	if(rc == NGX_OK)
		rc = NGX_HTTP_SLICE_MOD_SEEK;
	else if(rc == NGX_DONE)
		rc = NGX_HTTP_SLICE_MOD_DOWNLOAD;

	return rc;
}

static ngx_int_t 
ngx_http_mp4_plus_process_metadata(ngx_http_request_t* r, ngx_buf_t* metadata, ngx_http_slice_plus_metadata_t **result)
{
	ngx_int_t rc;
	ngx_http_mp4_plus_ctx_t *ctx;
		
       ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_plus_module);

       rc = ngx_http_mp4_plus_check_metadata(r, metadata);
       if(rc != NGX_OK)
	   	return rc;

	if(ctx->seek_type == NGX_HTTP_MP4_PLUS_SEEK_TYPE_TIME)
	{
		rc = ngx_http_mp4_plus_process_metadata_use_time_seek(r, metadata, result);
	}
	else if(ctx->seek_type == NGX_HTTP_MP4_PLUS_SEEK_TYPE_BYTES){
		return NGX_ERROR;
	}
       
	return rc;
}

static ngx_int_t 
ngx_http_mp4_plus_process_metadata_use_time_seek(ngx_http_request_t* r , ngx_buf_t* metadata, ngx_http_slice_plus_metadata_t **result)
{
	ngx_int_t rc;
	ngx_http_mp4_plus_ctx_t *ctx;
	ngx_uint_t start, end, length;
	ngx_http_mp4_file_t *mp4;
	ngx_http_mp4_range_t range;
	ngx_buf_t *buffer;
	u_char *p, *tmp;
	size_t usize;
	ngx_http_slice_plus_metadata_t *sm;
		
       ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_plus_module);
	buffer = metadata;
	
	ngx_http_mp4_plus_get_seek_time(ctx, &start, &end, &length);
	mp4 = ngx_pcalloc(r->pool, sizeof(ngx_http_mp4_file_t));
       if (mp4 == NULL) {
            return NGX_ERROR;
       }
	
	if((size_t)(buffer->end - buffer->last) < sizeof(ctx->metadata.mdat_head))
	{
		usize = buffer->last - buffer->start;
		p = ngx_palloc(r->pool,usize + sizeof(ctx->metadata.mdat_head));
		if(p == NULL)
			return NGX_ERROR;
		
		ngx_memcpy(p, buffer->start, usize);
		tmp = p + usize;
		
		ngx_pfree(r->pool, buffer->start);

		buffer->start =buffer->pos = p;
		buffer->last = tmp;
		buffer->end = tmp + sizeof(ctx->metadata.mdat_head);
	}

	ngx_memcpy(buffer->last, ctx->metadata.mdat_head, sizeof(ctx->metadata.mdat_head));
	buffer->last += sizeof(ctx->metadata.mdat_head);

	mp4->buffer = buffer->start;
	mp4->buffer_start = mp4->buffer;
	mp4->buffer_pos = mp4->buffer_start;
	mp4->buffer_end = buffer->last;
	mp4->buffer_size = mp4->buffer_end - mp4->buffer_start ;
	mp4->file.fd = 1;
       mp4->file.name = r->uri;
       mp4->file.log = r->connection->log;
       mp4->end = metadata->file_last;
	mp4->request = r;
       mp4->start = (ngx_uint_t) start;
       mp4->length = length;
	mp4->seek_directed = NGX_HTTP_MP4_SEEK_LEFT_DIRECTED;

	rc = ngx_http_mp4_process_metadata(r, mp4, &range);

	if(rc == NGX_OK)
	{
		sm = ngx_palloc(r->pool, sizeof(ngx_http_slice_plus_metadata_t));
		if(sm != NULL)
		{
		 	sm->mediadata_offset = range.start;
			sm->mediadata_length =  range.end - range.start;
		 	sm->metadata = mp4->out;
		 	sm->metadata_length = mp4->content_length - sm->mediadata_length;
			*result = sm;
		}
		else
			rc = NGX_ERROR;
	}

	return rc;
}

static void 
ngx_http_mp4_plus_get_seek_time(ngx_http_mp4_plus_ctx_t *ctx, ngx_uint_t *seek_start, ngx_uint_t *seek_end, ngx_uint_t *seek_length)
{
	ngx_uint_t start, end, length;
	
	start = ctx->seek_start ;
	end = ctx->seek_end ;
	length = 0;

	if(end > 0)
	{
		if(ctx->seek_preview > 0)
		{
			end = ngx_min(ctx->seek_preview, ctx->seek_end);
		}
	}
	else {
		end = ctx->seek_preview;
	}

	if(end > 0)
	{
		if(end < start)
			start = 0;
		length = end - start;
	}

	*seek_start = start;
	*seek_end = end;
	*seek_length = length;
}

static ngx_int_t 
ngx_http_mp4_plus_check_metadata(ngx_http_request_t* r , ngx_buf_t* metadata)
{
	ngx_int_t rc;
	ngx_http_mp4_plus_ctx_t *ctx;
	
       ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_plus_module);
	   
	do{
		rc = ngx_http_mp4_plus_read_atom(ctx, metadata);
		if((*(int*)ctx->metadata.mdat_head) != 0 && ctx->metadata.ftyp && ctx->metadata.moov)
		{
			return NGX_OK;
		}

		if(rc != NGX_OK)
			break;

	}while(metadata->last>metadata->pos);


	if(rc == NGX_ERROR || metadata->file_pos == metadata->file_last)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check metadata failed");
		return NGX_ERROR;
	}

	return NGX_AGAIN;
}

static ngx_int_t 
ngx_http_mp4_plus_get_number_var(ngx_variable_value_t* var, off_t *number)
{
	u_char p;
	off_t  n, cutoff, cutlim;
	ngx_int_t i;
	
	cutoff = NGX_MAX_OFF_T_VALUE / 10;
       cutlim = NGX_MAX_OFF_T_VALUE % 10;

       n = 0;
       for(i = 0; i < var->len; i++){
		p = var->data[i];
		if(!(p >= '0' && p <= '9'))
		{
			return NGX_ERROR;
		}
		if(n >= cutoff && (n > cutoff || p - '0' > cutlim))
		{
			return NGX_ERROR;
		}
		
		n = n * 10 + p++ - '0';
	}
	   
	*number = n;
	
	return NGX_OK;
}

static ngx_int_t
ngx_http_mp4_parse_variable(ngx_http_request_t *r)
{
	ngx_int_t rc;
	off_t start;
	off_t end;
       off_t preview;
       ngx_http_mp4_plus_ctx_t *ctx;
        ngx_http_mp4_plus_conf_t  *mpcf;

       mpcf = ngx_http_get_module_loc_conf(r, ngx_http_mp4_plus_module);
	   
       start = end = preview = -1;
       ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_plus_module);
	if(!ctx)
		return NGX_DONE;
	   
	if(ctx->var.seek_start)
	{
		rc = ngx_http_mp4_plus_get_number_var(ctx->var.seek_start, &start);
		if(rc == NGX_ERROR){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_start=%s parse error", ctx->var.seek_start->data);
			return rc;
		}
	}
	
	if(ctx->var.seek_end)
	{
		rc = ngx_http_mp4_plus_get_number_var(ctx->var.seek_end, &end);
		if(rc == NGX_ERROR){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_end=%s parse error", ctx->var.seek_end->data);
			return rc;
		}
		
		if(start > end){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_start=%s is biger than mp4_vod_seek_end=%s", ctx->var.seek_start->data, ctx->var.seek_end->data);
			return NGX_ERROR;
		}
	}
	
	if(ctx->var.seek_preview)
	{
		rc = ngx_http_mp4_plus_get_number_var(ctx->var.seek_preview, &preview);
		
		if(rc == NGX_ERROR || preview == 0){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_preview=%s parse error", ctx->var.seek_preview->data);
			return rc;
		}	
	}

	if(ctx->var.seek_type)
	{
		if(ctx->var.seek_type->data)
		{
			if(0 == ngx_strncasecmp(ctx->var.seek_type->data, (u_char*)"seek_bytes", ctx->var.seek_type->len))
			{
			       ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_type didnot be supported", ctx->var.seek_type->data);
				return NGX_ERROR;
				ctx->seek_type = NGX_HTTP_MP4_PLUS_SEEK_TYPE_BYTES;
			}
			else if(0 == ngx_strncasecmp(ctx->var.seek_type->data, (u_char*)"seek_time", ctx->var.seek_type->len))
			{
				ctx->seek_type = NGX_HTTP_MP4_PLUS_SEEK_TYPE_TIME;
			}
			else
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_type=%s parse error", ctx->var.seek_type->data);
				return NGX_ERROR;
			}
		}
	}
	
	if(ctx->var.seek_up)
	{
		if(ctx->var.seek_up->data)
		{
			if(0 == ngx_strncasecmp(ctx->var.seek_up->data, (u_char*)"seek_left_align", ctx->var.seek_up->len))
			{
				ctx->seek_up = NGX_HTTP_MP4_SEEK_LEFT_DIRECTED;
			}
			else if(0 == ngx_strncasecmp(ctx->var.seek_up->data, (u_char*)"seek_rigth_align", ctx->var.seek_up->len))
			{
				ctx->seek_up = NGX_HTTP_MP4_SEEK_RIGHT_DIRECTED;
			}
			else
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "mp4_vod_seek_up=%s parse error", ctx->var.seek_up->data);
				return NGX_ERROR;
			}
		}
	}
	

	if(end>=0)
	{
		if(start == -1)
			start = 0;
	}

	if(start <0 && preview == -1)
	{
		return NGX_DONE;
	}

	if(ctx->seek_type == NGX_HTTP_MP4_PLUS_SEEK_TYPE_TIME)
	{
		if((start > 0 && start > 0xFFFFFFFF) ||
		    (end > 0 && end > 0xFFFFFFFF) 
		){
			return NGX_ERROR;
		}
	}
	if(ctx->seek_up == 0)
	{
		ctx->seek_up = NGX_HTTP_MP4_SEEK_LEFT_DIRECTED;
	}

	ctx->seek_start = start;
	ctx->seek_end = end;
       ctx->seek_preview = preview;

	return NGX_OK;
}
	
static ngx_int_t
ngx_http_mp4_plus_read_atom(ngx_http_mp4_plus_ctx_t *ctx, ngx_buf_t* metadata)
{
	uint64_t     atom_size, atom_header_size, buf_size;
	u_char      *atom_header, *atom_name;
	ngx_buf_t *buf;
	
	atom_header_size = 8;
	buf = metadata;
	buf_size = buf->last-buf->pos;

	if(buf_size < atom_header_size){
		return NGX_AGAIN;
	}

	atom_header = buf->pos;
	atom_size = ngx_mp4_plus_get_32value(buf->pos);
	atom_name = atom_header + sizeof(uint32_t);
	       
	if (atom_size < 8)
	{
		if(atom_size != 1)
			return NGX_ERROR;
	

		atom_header_size = 16;
		if(buf_size < atom_header_size)
		{
			return NGX_AGAIN;
		}

		atom_size = ngx_mp4_plus_get_64value(buf->pos+8);
	}
	
	if(ngx_strncmp(atom_name, "ftyp", 4) == 0)
	{
		if(buf_size< atom_size)
		{
			return NGX_AGAIN;
		}
		ctx->metadata.ftyp = buf->pos;
		ctx->metadata.ftyp_size = atom_size;
		buf->pos += atom_size;
	}
	else if(ngx_strncmp(atom_name, "moov", 4) == 0)
	{
		if(buf_size< atom_size)
		{
			return NGX_AGAIN;
		}
		ctx->metadata.moov = buf->pos;
		ctx->metadata.moov_size = atom_size;
		buf->pos += atom_size;
	}
	else
	{
		if(ngx_strncmp(atom_name, "mdat", 4) == 0)
		{
			ngx_memcpy(ctx->metadata.mdat_head, buf->pos, atom_header_size);
		}
		
		if(buf_size >= atom_size)		
		{
			if(buf_size > atom_size)
				ngx_memcpy(buf->pos, buf->pos+atom_size, buf_size-atom_size);
			buf->last -= atom_size;
			
		}
		else
		{
			buf->last = buf->pos;
			buf->file_pos = buf->file_pos + atom_size - buf_size;
		}
		
		return NGX_OK;
	}

	return NGX_OK;
}


static void *
ngx_http_mp4_plus_create_conf(ngx_conf_t *cf)
{
    ngx_http_mp4_plus_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_mp4_plus_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->seek_keyframe = NGX_CONF_UNSET_SIZE;
 
    return conf;
}

static char *
ngx_http_mp4_plus_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mp4_plus_conf_t *prev = parent;
    ngx_http_mp4_plus_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->seek_keyframe, prev->seek_keyframe, 1);

    return NGX_CONF_OK;
}


