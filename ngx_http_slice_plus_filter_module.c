
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc
 * Copyright (C) zhaojunsong.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_slice_plus.h"
#include "assert.h"


typedef struct {
    off_t        start;
    off_t        end;
    ngx_str_t    content_range;
    ngx_flag_t boundary_sent;
}ngx_http_range_plus_t;

typedef struct {
    size_t                size;                         
    ngx_flag_t         check_etag;             // if 1 check etag
    size_t                buffer_size;            // metadata buffer
    size_t                max_buffer_size;   // metadata max buffer size

    ngx_http_slice_plus_metadata_handler_t *handler; 
} ngx_http_slice_plus_loc_conf_t;

typedef struct {
    off_t       start;
    off_t       end;
    ngx_str_t   range;
    ngx_str_t   etag;
    ngx_uint_t  last;  /* unsigned  last:1; */

    ngx_array_t ranges;
    ngx_uint_t index;           /*index of ranges*/
    ngx_str_t    boundary_header;
    off_t offset;
    ngx_flag_t multi_range;
    ngx_http_request_t *current_request;

    ngx_buf_t *buffer;
    ngx_int_t mod;     // seek or download

} ngx_http_slice_plus_ctx_t;


typedef struct {
    off_t       start;
    off_t       end;
    off_t       complete_length;
} ngx_http_slice_plus_content_range_t;


#define NGX_HTTP_SLICE_PLUS_DEFAULT_BUFFER_SIZE    512 * 1024
#define NGX_HTTP_SLICE_PLUS_DEFAULT_MAX_BUFFER_SIZE    1024 * 1024

static ngx_int_t ngx_http_slice_plus_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_slice_plus_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_slice_plus_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_plus_content_range_t *cr);
static ngx_int_t ngx_http_slice_plus_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_slice_plus_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_slice_plus_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_slice_plus_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_slice_plus_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_slice_plus_get_first_range(ngx_http_request_t *r, ngx_http_range_plus_t *range, size_t slice_size);
static ngx_int_t ngx_http_range_plus_parse(ngx_http_request_t *r, ngx_http_slice_plus_ctx_t *ctx,
    ngx_uint_t ranges);
static ngx_int_t ngx_http_range_plus_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_range_plus_singlepart_header(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx);
static ngx_int_t ngx_http_range_plus_multipart_header(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx);
static ngx_int_t ngx_http_range_plus_not_satisfiable(ngx_http_request_t *r);
static ngx_int_t ngx_http_range_plus_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_range_plus_singlepart_body(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx, ngx_chain_t *in);
static ngx_chain_t* ngx_http_range_plus_body_data_filter(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_range_plus_multipart_body(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_range_plus_test_overlapped(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx);
static ngx_int_t ngx_http_slice_plus_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_slice_plus_collect_data(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_slice_plus_process_cache_data(ngx_http_request_t *r, ngx_http_slice_plus_ctx_t *ctx, ngx_int_t rc);
static ngx_int_t ngx_http_slice_plus_variable_slice_plus(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_str_t  ngx_http_slice_plus_range_name = ngx_string("slice_plus_range");
static ngx_str_t  ngx_http_slice_plus_range_slice = ngx_string("slice_plus");

static ngx_http_variable_t ngx_http_slice_plus_vars[] = {
	{     ngx_string("slice_plus_range"), 
		NULL, 
		ngx_http_slice_plus_range_variable, 
		0, 
		NGX_HTTP_VAR_NOCACHEABLE, 
		0 },
		
	{ ngx_string("slice_plus"), 
		NULL, 
		ngx_http_slice_plus_variable_slice_plus, 
		0, 
		NGX_HTTP_VAR_NOCACHEABLE, 
		0 },

	{ ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t  ngx_http_slice_plus_filter_commands[] = {

    { ngx_string("slice_plus"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_plus_loc_conf_t, size),
      NULL },


    { ngx_string("slice_plus_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_plus_loc_conf_t, buffer_size),
      NULL },

    { ngx_string("slice_plus_max_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_plus_loc_conf_t, max_buffer_size),
      NULL },

    { ngx_string("slice_plus_check_etag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slice_plus_loc_conf_t, check_etag),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_slice_plus_range_name_ctx = {
    ngx_http_slice_plus_add_variables,          /* preconfiguration */
    ngx_http_slice_plus_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_slice_plus_create_loc_conf,        /* create location configuration */
    ngx_http_slice_plus_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_slice_plus_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_slice_plus_range_name_ctx,     /* module context */
    ngx_http_slice_plus_filter_commands,        /* module directives */
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

ngx_http_slice_plus_metadata_handler_t *metadata_handler ; 

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_slice_plus_header_filter(ngx_http_request_t *r)
{
    off_t                            end;
    ngx_int_t                        rc;
    ngx_table_elt_t                 *h;
    ngx_http_slice_plus_ctx_t            *ctx;
    ngx_http_slice_plus_loc_conf_t       *slcf;
    ngx_http_slice_plus_content_range_t   cr;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);

    if (r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT) {
        if (r == r->main) {
            ngx_http_set_ctx(r, NULL, ngx_http_slice_plus_filter_module);
            return ngx_http_next_header_filter(r);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    h = r->headers_out.etag;

    if (slcf->check_etag && ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || ngx_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "etag mismatch in slice response");
            return NGX_ERROR;
        }
    }

    if (h) {
        ctx->etag = h->value;
    }

    if (ngx_http_slice_plus_parse_content_range(r, &cr) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid range in slice response");
        return NGX_ERROR;
    }

    if (cr.complete_length == -1 || cr.complete_length == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no complete length in slice response");
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice response range: %O-%O/%O",
                   cr.start, cr.end, cr.complete_length);

    end = ngx_min(ctx->end , cr.complete_length);

    if (cr.start != ctx->start || cr.end != end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unexpected range in slice response: %O-%O",
                      cr.start, cr.end);
        return NGX_ERROR;
    }

    ctx->offset = cr.start;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_range->hash = 0;
    r->headers_out.content_range = NULL;
    r->allow_ranges = 0;
    r->subrequest_ranges = 1;

    if(ctx->mod == NGX_ERROR)
	return NGX_ERROR;
	
    if(ctx->mod & NGX_HTTP_SLICE_MOD_SEEK)
    {
        return NGX_OK;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.status_line.len = 0;
   
     rc = ngx_http_range_plus_header_filter(r);
  
    if (r != r->main) {
        return rc;
    }

    if(r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT)
    {
    	 ctx->end = cr.complete_length;
    }

    return rc;
}


static ngx_int_t
ngx_http_slice_plus_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                   rc;
    ngx_chain_t                *cl;
    ngx_http_request_t         *sr;
    ngx_http_slice_plus_ctx_t       *ctx;
    ngx_http_slice_plus_loc_conf_t  *slcf;
    ngx_http_range_plus_t  *range;
    off_t start;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);

    if (ctx == NULL ) {
        return ngx_http_next_body_filter(r, in);
    }

    if(r != r->main)
    {
        return ngx_http_range_plus_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = ngx_http_range_plus_body_filter(r, in);

    if (rc == NGX_ERROR || !ctx->last) {
        return rc;
    }

    if (ctx->ranges.nelts <= ctx->index) {
          if(ctx->mod & NGX_HTTP_SLICE_MOD_SEEK && !r->header_sent)
	  {
                rc = ngx_http_slice_plus_process_cache_data(r, ctx, NGX_OK);
		  if(rc == NGX_AGAIN)
		  	goto next_slice;
          }
		  
          ngx_http_set_ctx(r, NULL, ngx_http_slice_plus_filter_module);
          ngx_http_send_special(r, NGX_HTTP_LAST);
          return rc;
    }
	
next_slice:
	
    if (r->buffered) {
        return rc;
    }
	
    if(!(ctx->current_request->headers_out.status == NGX_HTTP_PARTIAL_CONTENT || 
           ctx->current_request->headers_out.status == NGX_HTTP_OK)){

       if(ctx->mod & NGX_HTTP_SLICE_MOD_SEEK && !r->header_sent){
		rc = ngx_http_slice_plus_process_cache_data(r, ctx,  ctx->current_request->headers_out.status);
	}
	
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream respone code invaild: %d", ctx->current_request->headers_out.status);
        return rc;
    }

    if (ngx_http_subrequest(r, &r->uri, &r->args, &sr, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->current_request = sr;
   
    ngx_http_set_ctx(sr, ctx, ngx_http_slice_plus_filter_module);

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);

    range = ctx->ranges.elts;
    ctx->start = range->start;
    ctx->end = ngx_min( (off_t)slcf->size * (ctx->start / (off_t)slcf->size) +  (off_t) slcf->size, range->end);


    ctx->range.len = ngx_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start, ctx->end- 1)
                              - ctx->range.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


static ngx_int_t
ngx_http_slice_plus_parse_content_range(ngx_http_request_t *r,
    ngx_http_slice_plus_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    ngx_table_elt_t  *h;

    h = r->headers_out.content_range;

    if (h == NULL
        || h->value.len < 7
        || ngx_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return NGX_ERROR;
    }

    p = h->value.data + 6;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        start = start * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NGX_ERROR;
        }

        end = end * 10 + *p++ - '0';
    }

    end++;

    while (*p == ' ') { p++; }

    if (*p++ != '/') {
        return NGX_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return NGX_ERROR;
            }

            complete_length = complete_length * 10 + *p++ - '0';
        }

    } else {
        complete_length = -1;
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NGX_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return NGX_OK;
}

static ngx_int_t
ngx_http_slice_plus_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_http_slice_plus_ctx_t       *ctx;
    ngx_http_slice_plus_loc_conf_t  *slcf;
    ngx_int_t rc;
    off_t start;
    ngx_http_range_plus_t range;
    ngx_http_variable_t  *var;
	
    range.start = range.end =-1;
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);

    if (ctx == NULL) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return NGX_OK;
        }

        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_slice_plus_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_array_init(&ctx->ranges, r->pool, 1,  sizeof(ngx_http_range_plus_t));
        if(rc != NGX_OK)
              return rc;

        ngx_http_set_ctx(r, ctx, ngx_http_slice_plus_filter_module);

        p = ngx_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }
        ctx->range.data = p;
     
        ngx_http_slice_plus_get_first_range(r, &range, slcf->size);
        ctx->start = range.start;
        ctx->end = range.end;
        ctx->range.len = ngx_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start, ctx->end-1) - ctx->range.data;
        ctx->current_request = r;
    }

    var = (ngx_http_variable_t*)data;
    if(var->name.len == ngx_http_slice_plus_range_name.len && 
        ngx_strncmp(var->name.data, ngx_http_slice_plus_range_name.data, var->name.len) == 0)
    {
        v->data = ctx->range.data;
        v->valid = 1;
        v->not_found = 0;
        v->no_cacheable = 1;
        v->len = ctx->range.len;
    }
    else
        return NGX_ERROR;
	
    return NGX_OK;
}

static ngx_int_t 
ngx_http_slice_plus_get_first_range(ngx_http_request_t *r, ngx_http_range_plus_t *range, size_t slice_size)
{
    off_t             start, cutoff, cutlim, end;
    u_char           *p;
    ngx_table_elt_t  *h;
    ngx_http_slice_plus_loc_conf_t  *slcf;
    ngx_http_slice_plus_ctx_t       *ctx;
    ngx_http_range_plus_t  *first_range;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);

    if(metadata_handler != NULL)
	ctx->mod = metadata_handler->get_mod(r);

    if(ctx->mod == NGX_ERROR)
   	goto default_range;
	
    if(ctx->mod & NGX_HTTP_SLICE_MOD_SEEK)
    {
        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);
        first_range = ngx_array_push(&ctx->ranges);
        if(first_range == NULL)
		return NGX_ERROR;

        first_range->start = 0;
        first_range->end = slcf->buffer_size;
	 range->start = 0;
        range->end = slice_size;
	 return NGX_OK;
    }

    if (r->headers_in.if_range) {
        goto default_range;
    }

    h = r->headers_in.range;
    if(h == NULL)
    {
      range->start = 0;
      range->end = slice_size;
      return NGX_OK;
    }

    if (h->value.len < 7
        || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        goto default_range;
    }
    
    p = h->value.data + 6;

    while (*p == ' ') { p++; }

    if (*p == '-' || *p < '0' || *p > '9') {
       goto default_range;
    }

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
           goto default_range;
        }

        start = start * 10 + *p++ - '0';
    }

    range->start = start;

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
           goto default_range;
    }

    end = 0;
    
    while (*p == ' ') { p++; }
   

    if(*p == '\0' || *p==',')
    {
        end = slice_size * (start / slice_size) +  (off_t) slice_size;
        range->end = end;
        return NGX_OK;
    }

    if (*p < '0' || *p > '9') {
    
           goto default_range;
    }

    while (*p >= '0' && *p <= '9') {
          if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
                   goto default_range;
          }

          end = end * 10 + *p++ - '0';
    }

    end++;
    
    if(start < end)
    {
    range->start = start;
    range->end = ngx_min( (off_t)slice_size * (start /  (off_t)slice_size) +  (off_t) slice_size, end);
    return NGX_OK;
    }

    
default_range:
    range->start = 0;
    range->end = 1;
    return NGX_AGAIN;
}

static void *
ngx_http_slice_plus_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_slice_plus_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_slice_plus_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = NGX_CONF_UNSET_SIZE;
    slcf->check_etag = NGX_CONF_UNSET_SIZE;
    slcf->max_buffer_size = NGX_CONF_UNSET_SIZE;
    slcf->buffer_size = NGX_CONF_UNSET_SIZE;
    slcf->handler = NGX_CONF_UNSET_PTR;
	
	
    return slcf;
}

static char *
ngx_http_slice_plus_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_slice_plus_loc_conf_t *prev = parent;
    ngx_http_slice_plus_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->size, prev->size, 0);
    ngx_conf_merge_value(conf->check_etag, prev->check_etag, 1);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, NGX_HTTP_SLICE_PLUS_DEFAULT_BUFFER_SIZE);
    ngx_conf_merge_size_value(conf->max_buffer_size, prev->max_buffer_size, NGX_HTTP_SLICE_PLUS_DEFAULT_MAX_BUFFER_SIZE);
	
    if(conf->buffer_size >= conf->max_buffer_size)
    {
        conf->max_buffer_size = conf->buffer_size;
    }

    if(conf->buffer_size <= NGX_MAX_ALLOC_FROM_POOL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"mp4_plus_buffer_size\" must be  greater than %d", NGX_MAX_ALLOC_FROM_POOL);
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

/**
    Ìí¼Ó±äÁ¿
*/
static ngx_int_t
ngx_http_slice_plus_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_slice_plus_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, 0);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->set_handler = v->set_handler;
		var->data = (uintptr_t)var;
		var->flags = v->flags;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_range_plus_parse(ngx_http_request_t *r, ngx_http_slice_plus_ctx_t *ctx,
    ngx_uint_t ranges)
{
    u_char                       *p;
    off_t                         start, end, size, content_length, cutoff,
                                  cutlim;
    ngx_uint_t                    suffix;
    ngx_http_range_plus_t             *range;

    p = r->headers_in.range->value.data + 6;
    size = 0;
    content_length = r->headers_out.content_length_n;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;

        while (*p == ' ') { p++; }

        if (*p != '-') { 
            if (*p < '0' || *p > '9') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p >= '0' && *p <= '9') {
                if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }

                start = start * 10 + *p++ - '0';
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                end = content_length;
                goto found;
            }
        }
    else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            end = end * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        if (suffix) {
            start = content_length - end;
            end = content_length - 1;
        }

        if (end >= content_length) {
            end = content_length;

        } else {
            end++;
        }

    found:

        if (start < end) {
            range = ngx_array_push(&ctx->ranges);
            if (range == NULL) {
                return NGX_ERROR;
            }

            range->start = start;
            range->end = end;
            range->boundary_sent = 0;
            
            size += end - start;

            if (ranges-- == 0) {
                return NGX_DECLINED;
            }
        }
    else{
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

        if (*p++ != ',') {
            break;
        }
    }

    if (ctx->ranges.nelts == 0) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (size > content_length) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if(NGX_OK != ngx_http_range_plus_test_overlapped(r, ctx))
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_range_plus_header_filter(ngx_http_request_t *r)
{
    time_t                        if_range_time;
    ngx_str_t                    *if_range, *etag;
    ngx_uint_t                    ranges;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_slice_plus_ctx_t  *ctx;
    ngx_http_range_plus_t *range;

    if(r != r->main || r->headers_out.status != NGX_HTTP_OK)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);

    if (r->http_version < NGX_HTTP_VERSION_10)
    {
         goto auto_slice;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->max_ranges == 0) {
        goto auto_slice;
    }

    if (r->headers_in.range == NULL 
        || r->headers_in.range->value.len < 7  
        || ngx_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6)
           != 0)
    {
        goto next_filter;
    }

    if (r->headers_in.if_range) { 

        if_range = &r->headers_in.if_range->value;

        if (if_range->len >= 2 && if_range->data[if_range->len - 1] == '"') { 
            if (r->headers_out.etag == NULL) { 
                goto next_filter;
            }

            etag = &r->headers_out.etag->value;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ir:%V etag:%V", if_range, etag);

            if (if_range->len != etag->len
                || ngx_strncmp(if_range->data, etag->data, etag->len) != 0)
            {
                  if(r != r->main)
                  {
                      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "etag changed");
              		return NGX_ERROR;
                  }      
                  goto next_filter;
            }

            goto parse;
        }

        if (r->headers_out.last_modified_time == (time_t) -1) {
            goto next_filter;
        }

        if_range_time = ngx_http_parse_time(if_range->data, if_range->len);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http ir:%d lm:%d",
                       if_range_time, r->headers_out.last_modified_time);

        if (if_range_time != r->headers_out.last_modified_time) {
         if(r != r->main)
         {
                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "last_modified_time changed");
              return NGX_ERROR;
         }
            goto next_filter;
        }
    }

parse:

    ranges =  clcf->max_ranges;

    switch (ngx_http_range_plus_parse(r, ctx, ranges)) {

    case NGX_OK:
    
        r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
        r->headers_out.status_line.len = 0;

        if (ctx->ranges.nelts == 1) {
            return ngx_http_range_plus_singlepart_header(r, ctx);
        }
	 if(0)
            return ngx_http_range_plus_multipart_header(r, ctx);

    case NGX_HTTP_RANGE_NOT_SATISFIABLE:
        return ngx_http_range_plus_not_satisfiable(r);

    case NGX_ERROR:
        return NGX_ERROR;

    default: /* NGX_DECLINED */
        break;
    }

next_filter:

    r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.accept_ranges == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.accept_ranges->hash = 1;
    ngx_str_set(&r->headers_out.accept_ranges->key, "Accept-Ranges");
    ngx_str_set(&r->headers_out.accept_ranges->value, "bytes");

auto_slice:
    range = ngx_array_push(&ctx->ranges);
    if(range == NULL)
      return NGX_ERROR;

    range->start = 0;
    range->end = r->headers_out.content_length_n;
   
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_range_plus_singlepart_header(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx)
{
    ngx_table_elt_t   *content_range;
    ngx_http_range_plus_t  *range;

    content_range = ngx_list_push(&r->headers_out.headers);
    if (content_range == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_range = content_range;

    content_range->hash = 1;
    ngx_str_set(&content_range->key, "Content-Range");

    content_range->value.data = ngx_pnalloc(r->pool,
                                    sizeof("bytes -/") - 1 + 3 * NGX_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        return NGX_ERROR;
    }

    /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

    range = ctx->ranges.elts;

    content_range->value.len = ngx_sprintf(content_range->value.data,
                                           "bytes %O-%O/%O",
                                           range->start, range->end - 1,
                                           r->headers_out.content_length_n)
                               - content_range->value.data;

    r->headers_out.content_length_n = range->end - range->start;  

    //r->headers_out.content_offset = range->start;

    if (r->headers_out.content_length) {  
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_range_plus_multipart_header(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx)
{
    ngx_atomic_uint_t   boundary;
    size_t len;
    size_t              size;
    ngx_http_range_plus_t   *range;
    ngx_uint_t          i;
    
    size = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
          + sizeof(CRLF "Content-Type: ") - 1
          + r->headers_out.content_type.len
          + sizeof(CRLF "Content-Range: bytes ") - 1;

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        size += sizeof("; charset=") - 1 + r->headers_out.charset.len;
    }

    ctx->boundary_header.data = ngx_pnalloc(r->pool, size);
    if (ctx->boundary_header.data == NULL) {
        return NGX_ERROR;
    }

    ctx->multi_range = 1;
    boundary = ngx_next_temp_number(0);
   
    /*
     * The boundary header of the range:
     * CRLF
     * "--0123456789" CRLF
     * "Content-Type: image/jpeg" CRLF
     * "Content-Range: bytes "
     */
    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V; charset=%V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type,
                                           &r->headers_out.charset)
                                   - ctx->boundary_header.data;

    } else if (r->headers_out.content_type.len) {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type)
                                   - ctx->boundary_header.data;

    } else {
        ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Range: bytes ",
                                           boundary)
                                   - ctx->boundary_header.data;
    }

    r->headers_out.content_type.data =
        ngx_pnalloc(r->pool,
                    sizeof("Content-Type: multipart/byteranges; boundary=") - 1
                    + NGX_ATOMIC_T_LEN);

    if (r->headers_out.content_type.data == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_type_lowcase = NULL;

    /* "Content-Type: multipart/byteranges; boundary=0123456789" */

    r->headers_out.content_type.len =
                           ngx_sprintf(r->headers_out.content_type.data,
                                       "multipart/byteranges; boundary=%0muA",
                                       boundary)
                           - r->headers_out.content_type.data;

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.charset.len = 0;


    /* the size of the last boundary CRLF "--0123456789--" CRLF */

    len = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN + sizeof("--" CRLF) - 1;

    range = ctx->ranges.elts;
    for (i = 0; i < ctx->ranges.nelts; i++) {

        /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

        range[i].content_range.data =
                               ngx_pnalloc(r->pool, 3 * NGX_OFF_T_LEN + 2 + 4);

        if (range[i].content_range.data == NULL) {
            return NGX_ERROR;
        }

        range[i].content_range.len = ngx_sprintf(range[i].content_range.data,
                                               "%O-%O/%O" CRLF CRLF,
                                               range[i].start, range[i].end - 1,
                                               r->headers_out.content_length_n)
                                     - range[i].content_range.data;

        len += ctx->boundary_header.len + range[i].content_range.len
                                             + (range[i].end - range[i].start);
    
    }
	
    r->headers_out.content_length_n = len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return  ngx_http_next_header_filter(r);;
}

static ngx_int_t
ngx_http_range_plus_not_satisfiable(ngx_http_request_t *r)
{
    ngx_table_elt_t  *content_range;

    r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;

    content_range = ngx_list_push(&r->headers_out.headers);
    if (content_range == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_range = content_range;

    content_range->hash = 1;
    ngx_str_set(&content_range->key, "Content-Range");

    content_range->value.data = ngx_pnalloc(r->pool,
                                       sizeof("bytes */") - 1 + NGX_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        return NGX_ERROR;
    }

    content_range->value.len = ngx_sprintf(content_range->value.data,
                                           "bytes */%O",
                                           r->headers_out.content_length_n)
                               - content_range->value.data;

    ngx_http_clear_content_length(r);

    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
}

static ngx_int_t
ngx_http_range_plus_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_slice_plus_ctx_t  *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);
    
    if (in == NULL || ctx->ranges.nelts == 0) {
        return ngx_http_slice_plus_next_body_filter(r, in);
    }

    if (ctx->multi_range == 0) {
        return ngx_http_range_plus_singlepart_body(r, ctx, in);
    }

    return ngx_http_range_plus_multipart_body(r, ctx, in);
}

static ngx_int_t 
ngx_http_range_plus_singlepart_body(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx, ngx_chain_t *in)
{
    in = ngx_http_range_plus_body_data_filter(r, ctx, in);
    if(in == NULL)
        return NGX_OK;

    return ngx_http_slice_plus_next_body_filter(r, in);
}

static ngx_chain_t *
ngx_http_range_plus_body_data_filter(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx, ngx_chain_t *in)
{
    off_t              start, last;
    ngx_buf_t         *buf;
    ngx_chain_t       *out, *cl, **ll;
    ngx_http_range_plus_t  *range;

    out = NULL;
    ll = &out;
    range = (ngx_http_range_plus_t*)ctx->ranges.elts + ctx->index;

    if(ctx->current_request  != r)
        return out;

    for (cl = in; cl; cl = cl->next) {

        buf = cl->buf;
        start = ctx->offset;
        last = ctx->offset + ngx_buf_size(buf);

        ctx->offset = last;
     
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http range body buf: %O-%O", start, last);

        if (ngx_buf_special(buf)) {
            *ll = cl;
            ll = &cl->next;
            continue;
        }

        if (range->end <= start || range->start >= last) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http range body skip");

            if (buf->in_file) {
                buf->file_pos = buf->file_last;
            }

            buf->pos = buf->last;
            buf->sync = 1;
			
            continue;
        }
                        
        if (range->start > start) {

            if (buf->in_file) {
                buf->file_pos += range->start - start;
            }

            if (ngx_buf_in_memory(buf)) {
                buf->pos += (size_t) (range->start - start);
            }

            range->start = ctx->offset;
        }

        if (range->end <= last) {

            if (buf->in_file) {
                buf->file_last -= last - range->end;
            }

            if (ngx_buf_in_memory(buf)) {
                buf->last -= (size_t) (last - range->end);
            }

            buf->last_buf = 1;
            *ll = cl;
            cl->next = NULL;

	     ctx->index ++;
            //ctx->ranges.elts = (ngx_http_range_plus_t*)ctx->ranges.elts + 1;
            //ctx->ranges.nelts --;
         
            break;
        }

        *ll = cl;
        ll = &cl->next;

     range->start = ctx->offset;
    }

    return out;
}


static ngx_int_t
ngx_http_range_plus_multipart_body(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_http_range_plus_t  *range;
    ngx_buf_t         *b;
    ngx_chain_t  *hcl, *rcl, **ll, c;

    
    range = ctx->ranges.elts;
    
    in = ngx_http_range_plus_body_data_filter(r, ctx, in);
    if(in == NULL)
         return NGX_OK;

    ll = &in->next;
   
    if(range->boundary_sent == 0)
    {
       /*
         * The boundary header of the range:
         * CRLF
         * "--0123456789" CRLF
         * "Content-Type: image/jpeg" CRLF
         * "Content-Range: bytes "
         */
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = ctx->boundary_header.data;
        b->last = ctx->boundary_header.data + ctx->boundary_header.len;

        hcl = ngx_alloc_chain_link(r->pool);
        if (hcl == NULL) {
            return NGX_ERROR;
        }

        hcl->buf = b;


        /* "SSSS-EEEE/TTTT" CRLF CRLF */

	 b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->temporary = 1;
        b->pos = range->content_range.data;
        b->last = range->content_range.data + range->content_range.len;

        rcl = ngx_alloc_chain_link(r->pool);
        if (rcl == NULL) {
            return NGX_ERROR;
        }

        rcl->buf = b;

        range->boundary_sent = 1;

        hcl->next = rcl;
        rcl->next = in;
        in = hcl;     
    }

    
    if(ctx->ranges.nelts == ctx->index)
    {
        b = ngx_create_temp_buf(r->pool,  sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
                                                          + sizeof("--" CRLF) - 1);
        if (b == NULL) {
            return NGX_ERROR;
        }
        
        b->last_buf = 1;
        b->last = ngx_cpymem(b->pos, ctx->boundary_header.data,
                         sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN);
        *b->last++ = '-'; *b->last++ = '-';
        *b->last++ = CR; *b->last++ = LF;

        c.buf = b;
        c.next = NULL;

        if(NGX_OK != ngx_chain_add_copy(r->pool, &in, &c))
            return NGX_ERROR;
    }

    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_range_plus_test_overlapped(ngx_http_request_t *r,
    ngx_http_slice_plus_ctx_t *ctx)
{
    ngx_uint_t         i,j;
    ngx_http_range_plus_t  *range1, *range2;

    for(i=0; i < ctx->ranges.nelts-1; i++){
        range1 = (ngx_http_range_plus_t*)ctx->ranges.elts+i;
     for(j=i+1; j<ctx->ranges.nelts; j++)
     {
        range2 = (ngx_http_range_plus_t*)ctx->ranges.elts+j;
        if(!(range1->start>=range2->end || range2->start>=range1->end))
            goto overlapped;
     }
    }

    return NGX_OK;

overlapped:

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,  "overlapped range");

    return NGX_ERROR;
}

static ngx_int_t 
ngx_http_slice_plus_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{    
    ngx_http_slice_plus_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);

    if(ctx->mod & NGX_HTTP_SLICE_MOD_DOWNLOAD || r->main->header_sent)
    {
        return ngx_http_next_body_filter(r, in);
    }

    return ngx_http_slice_plus_collect_data(r, in);
}

/*
	cache metadata
*/
static ngx_int_t 
ngx_http_slice_plus_collect_data(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *c;
    size_t size, bsize, asize, nsize;
    ngx_http_slice_plus_loc_conf_t *slcf;
    ngx_http_slice_plus_ctx_t *ctx;
    u_char* p;
    void* tmp;

    ctx = ngx_http_get_module_ctx(r, ngx_http_slice_plus_filter_module);
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);

    for(c = in; c; c=c->next)
    {
        if (ngx_buf_special(c->buf)) {
            goto clear;
        }

	 assert(ngx_buf_in_memory(c->buf));
	
        size = ngx_buf_size(c->buf);
	 if(size == 0){
            continue;
	 }
	 
        if(!ctx->buffer)
        {
              ctx->buffer = ngx_create_temp_buf(r->pool, slcf->buffer_size);
		if(ctx->buffer == NULL)
              	return NGX_ERROR;
		 ctx->buffer->file_last = r->headers_out.content_length_n;
	 }

    	 bsize = (size_t)(ctx->buffer->end - ctx->buffer->start); //buffer size
	 asize = (size_t)(ctx->buffer->end - ctx->buffer->last);  //available size
	 nsize = size -asize;                                                       //need size

	 if(asize < size)
	 {
             if(bsize == slcf->max_buffer_size || bsize + nsize > slcf->max_buffer_size)
             {
		  return NGX_ERROR;
	      }
            
	      bsize = ((nsize % slcf->buffer_size) + 1) * slcf->buffer_size + bsize;
             bsize = ngx_min(bsize, slcf->max_buffer_size);
			 
             p = ngx_pcalloc(r->pool, bsize);
	      if(p == NULL)
		  	return NGX_ERROR;
		  
             tmp = ctx->buffer->start;
             ngx_memcpy(p, ctx->buffer->start, ctx->buffer->last-ctx->buffer->start);
	      
             ctx->buffer->pos = p + (ctx->buffer->pos - ctx->buffer->start);
             ctx->buffer->last = p + (ctx->buffer->last - ctx->buffer->start);
	      ctx->buffer->start = p;
             ctx->buffer->end = p + bsize;
	      
	      ngx_pfree(r->pool, tmp);
	  }


         ngx_memcpy(ctx->buffer->last,  c->buf->pos,  size);
         ctx->buffer->last += size;
	  ctx->buffer->file_pos += size;
	  
clear:

         c->buf->pos = c->buf->last;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_slice_plus_process_metadata(ngx_http_request_t *r, ngx_http_slice_plus_ctx_t *ctx, ngx_http_slice_plus_metadata_t **result)
{
    ngx_http_slice_plus_loc_conf_t  *slcf;
    ngx_http_range_plus_t *range;
    ngx_int_t rc;
    size_t asize, bsize, nsize;
	
    // reset array
    ctx->ranges.nelts = 0;
    ctx->index = 0;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);

    rc = metadata_handler->process_metatdata(r, ctx->buffer, result);
    if(rc == NGX_OK || rc == NGX_ERROR)
		return rc;

    //NGX_AGAIN, alloc larger space

    asize = (size_t)(ctx->buffer->end - ctx->buffer->last); //avaliable size
    range = ngx_array_push(&ctx->ranges);
    range->start = ctx->buffer->file_pos;
    if(asize == 0)
    {
    	 bsize = (size_t)(ctx->buffer->end - ctx->buffer->start);//buffer size
        if(bsize == slcf->max_buffer_size)
	 {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "metadata is too larger");
		return NGX_ERROR;
	 }
	
        nsize  = bsize + slcf->buffer_size;  // new buffer size;
	 nsize = ngx_min(nsize, slcf->max_buffer_size);
	 asize = nsize - bsize;
     }


     range->end = range->start + asize ;

     if(range->end > ctx->buffer->file_last)
     {
	 range->end = ctx->buffer->file_last;
     }
	
    return NGX_AGAIN;
}

/*
	process cache data
	if rc is NGX_OK , process metadata ,otherwise send respone header 
*/
static ngx_int_t
ngx_http_slice_plus_process_cache_data(ngx_http_request_t *r, ngx_http_slice_plus_ctx_t *ctx, ngx_int_t rc)
{
     ngx_uint_t i;
     ngx_http_slice_plus_metadata_t *result;
     ngx_http_range_plus_t *range;
     size_t length;

    if(rc == NGX_OK)  
    	rc = ngx_http_slice_plus_process_metadata(r, ctx,  &result);
    
    if(rc == NGX_AGAIN)
        return rc;
	
    if(rc == NGX_OK)
    {
    	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = result->metadata_length+result->mediadata_length;
	if( r->headers_out.content_range)
       {
    	    r->headers_out.content_range->hash = 0;
    	    r->headers_out.content_range = NULL;
       }
    }
    else
    {
	r->headers_out.status = NGX_HTTP_FORBIDDEN;
	r->headers_out.content_length_n = 0;
	r->headers_out.headers.part.nelts = 0;
    }
    
    r->allow_ranges = 0;
    r->subrequest_ranges = 1;
    r->headers_out.status_line.len = 0;
    r->out = NULL;
	
    rc = ngx_http_range_plus_header_filter(r);

    if(rc == NGX_ERROR || rc > NGX_OK)
        return rc;

    if(r->headers_out.content_length_n == 0)
    {
        return ngx_http_write_filter(r, NULL);
    }
    ctx->offset = 0;
    ctx->current_request = r;
    rc = ngx_http_range_plus_body_filter(r, result->metadata);
    if(rc == NGX_ERROR)
	return rc;

    
    if(ctx->ranges.nelts && ctx->index < ctx->ranges.nelts)
    {
        assert(ctx->ranges.nelts == 1 && 
       	(r->headers_out.status == NGX_HTTP_OK || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT)
	   );

        for(i=ctx->index; i<ctx->ranges.nelts; i++)
        {  
              range = (ngx_http_range_plus_t*)ctx->ranges.elts + i;
	       length = range->end - range->start;
	 	range->start = result->mediadata_offset + (range->start - result->metadata_length);
	 	range->end = range->start + length;
        }

	 return NGX_AGAIN;
    }

    return NGX_OK;
}

/*slice variable getter*/
static ngx_int_t
ngx_http_slice_plus_variable_slice_plus(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
	 ngx_http_slice_plus_loc_conf_t  *slcf;
	 u_char* p;
	 
        slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_plus_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

	 p = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%z", slcf->size) - p;
	 v->data = p;
        v->valid = 1;
        v->not_found = 0;
        v->no_cacheable = 1;

	 return NGX_OK;
}

static ngx_int_t
ngx_http_slice_plus_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_slice_plus_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_slice_plus_body_filter;

    return NGX_OK;
}


