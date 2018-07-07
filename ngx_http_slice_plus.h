/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc
 * Copyright (C) zhaojunsong.
 */

#ifndef NGX_HTTP_MP4_SLICE_PLUS_H_
#define NGX_HTTP_MP4_SLICE_PLUS_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SLICE_MOD_DOWNLOAD  0    
#define NGX_HTTP_SLICE_MOD_SEEK    1            

typedef struct {
    ngx_chain_t* metadata;
    size_t           metadata_length;
    off_t             mediadata_offset;
    size_t           mediadata_length;
} ngx_http_slice_plus_metadata_t;

typedef ngx_int_t (*ngx_http_slice_plus_get_mod_pt)
    (ngx_http_request_t* r);

typedef ngx_int_t (*ngx_http_slice_plus_process_metadata_pt)
    (ngx_http_request_t* r , ngx_buf_t* metadata, ngx_http_slice_plus_metadata_t **result);

typedef struct {
    ngx_http_slice_plus_get_mod_pt               get_mod;
    ngx_http_slice_plus_process_metadata_pt process_metatdata;
} ngx_http_slice_plus_metadata_handler_t;

extern ngx_http_slice_plus_metadata_handler_t *metadata_handler; 

#endif
