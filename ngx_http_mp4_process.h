/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) zhaojunsong.
 */


#ifndef _NGX_HTTP_MP4_PROCESS_H_INCLUDED_
#define _NGX_HTTP_MP4_PROCESS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_MP4_TRAK_ATOM     0
#define NGX_HTTP_MP4_TKHD_ATOM     1
#define NGX_HTTP_MP4_MDIA_ATOM     2
#define NGX_HTTP_MP4_MDHD_ATOM     3
#define NGX_HTTP_MP4_HDLR_ATOM     4
#define NGX_HTTP_MP4_MINF_ATOM     5
#define NGX_HTTP_MP4_VMHD_ATOM     6
#define NGX_HTTP_MP4_SMHD_ATOM     7
#define NGX_HTTP_MP4_DINF_ATOM     8
#define NGX_HTTP_MP4_STBL_ATOM     9
#define NGX_HTTP_MP4_STSD_ATOM    10
#define NGX_HTTP_MP4_STTS_ATOM    11
#define NGX_HTTP_MP4_STTS_DATA    12
#define NGX_HTTP_MP4_STSS_ATOM    13
#define NGX_HTTP_MP4_STSS_DATA    14
#define NGX_HTTP_MP4_CTTS_ATOM    15
#define NGX_HTTP_MP4_CTTS_DATA    16
#define NGX_HTTP_MP4_STSC_ATOM    17
#define NGX_HTTP_MP4_STSC_START   18
#define NGX_HTTP_MP4_STSC_DATA    19
#define NGX_HTTP_MP4_STSC_END     20
#define NGX_HTTP_MP4_STSZ_ATOM    21
#define NGX_HTTP_MP4_STSZ_DATA    22
#define NGX_HTTP_MP4_STCO_ATOM    23
#define NGX_HTTP_MP4_STCO_DATA    24
#define NGX_HTTP_MP4_CO64_ATOM    25
#define NGX_HTTP_MP4_CO64_DATA    26

#define NGX_HTTP_MP4_LAST_ATOM    NGX_HTTP_MP4_CO64_DATA

#define NGX_HTTP_MP4_VIDEO_TRACK    1
#define NGX_HTTP_MP4_AUDIO_TRACK    2
#define NGX_HTTP_MP4_HINT_TRACK     3
#define NGX_HTTP_MP4_UNKNOWN_TRACK -1

#define NGX_HTTP_MP4_SEEK_LEFT_DIRECTED    1
#define NGX_HTTP_MP4_SEEK_RIGHT_DIRECTED   2
#define NGX_HTTP_MP4_SLICE_SIZE           (4*1024*1024)

typedef struct {
    u_char                chunk[4];
    u_char                samples[4];
    u_char                id[4];
} ngx_mp4_stsc_entry_t;

typedef struct {
    uint32_t              timescale;
    uint32_t              time_to_sample_entries;
    uint32_t              sample_to_chunk_entries;
    uint32_t              sync_samples_entries;
    uint32_t              composition_offset_entries;
    uint32_t              sample_sizes_entries;
    uint32_t              chunks;
    
    ngx_uint_t            trak_id;
    ngx_uint_t            trak_media_type;
    ngx_uint_t            start_sample;
    ngx_uint_t            end_sample;
    ngx_uint_t            start_chunk;
    ngx_uint_t            end_chunk;
    ngx_uint_t            start_chunk_samples;
    ngx_uint_t            end_chunk_samples;
    uint64_t              start_chunk_samples_size;
    uint64_t              end_chunk_samples_size;
    off_t                 start_offset;
    off_t                 end_offset;

    size_t                tkhd_size;
    size_t                mdhd_size;
    size_t                hdlr_size;
    size_t                vmhd_size;
    size_t                smhd_size;
    size_t                dinf_size;
    size_t                size;

    ngx_chain_t           out[NGX_HTTP_MP4_LAST_ATOM + 1];
    ngx_array_t           stts_samples;
    ngx_array_t           stss_samples;

    ngx_buf_t             trak_atom_buf;
    ngx_buf_t             tkhd_atom_buf;
    ngx_buf_t             mdia_atom_buf;
    ngx_buf_t             mdhd_atom_buf;
    ngx_buf_t             hdlr_atom_buf;
    ngx_buf_t             minf_atom_buf;
    ngx_buf_t             vmhd_atom_buf;
    ngx_buf_t             smhd_atom_buf;
    ngx_buf_t             dinf_atom_buf;
    ngx_buf_t             stbl_atom_buf;
    ngx_buf_t             stsd_atom_buf;
    ngx_buf_t             stts_atom_buf;
    ngx_buf_t             stts_data_buf;
    ngx_buf_t             stss_atom_buf;
    ngx_buf_t             stss_data_buf;
    ngx_buf_t             ctts_atom_buf;
    ngx_buf_t             ctts_data_buf;
    ngx_buf_t             stsc_atom_buf;
    ngx_buf_t             stsc_start_chunk_buf;
    ngx_buf_t             stsc_end_chunk_buf;
    ngx_buf_t             stsc_data_buf;
    ngx_buf_t             stsz_atom_buf;
    ngx_buf_t             stsz_data_buf;
    ngx_buf_t             stco_atom_buf;
    ngx_buf_t             stco_data_buf;
    ngx_buf_t             co64_atom_buf;
    ngx_buf_t             co64_data_buf;

    ngx_mp4_stsc_entry_t  stsc_start_chunk_entry;
    ngx_mp4_stsc_entry_t  stsc_end_chunk_entry;
} ngx_http_mp4_trak_t;

typedef struct {
    ngx_file_t            file;

    u_char               *buffer;
    u_char               *buffer_start;
    u_char               *buffer_pos;
    u_char               *buffer_end;
    size_t                buffer_size;
    
    ngx_uint_t            video_sync_start;          

    ngx_uint_t            slice_size;
    ngx_uint_t            max_buffer_size;

    ngx_int_t             seek_directed;

    off_t                 offset;
    off_t                 end;
    off_t                 content_length;
    ngx_uint_t            start;
    ngx_uint_t            length;
    uint32_t              timescale;
    ngx_http_request_t   *request;
    ngx_array_t           trak;
    ngx_http_mp4_trak_t   traks[2];

    size_t                ftyp_size;
    size_t                moov_size;

    ngx_chain_t          *out;
    ngx_chain_t           ftyp_atom;
    ngx_chain_t           moov_atom;
    ngx_chain_t           mvhd_atom;
    ngx_chain_t           mdat_atom;
    ngx_chain_t           mdat_data;

    ngx_buf_t             ftyp_atom_buf;
    ngx_buf_t             moov_atom_buf;
    ngx_buf_t             mvhd_atom_buf;
    ngx_buf_t             mdat_atom_buf;
    ngx_buf_t             mdat_data_buf;

    u_char                moov_atom_header[8];
    u_char                mdat_atom_header[16];
} ngx_http_mp4_file_t;


typedef struct ngx_http_mp4_range_s {
    ngx_uint_t start;
    ngx_uint_t end;
} ngx_http_mp4_range_t;


/**
 *   ngx_buf_t             *buf    = metadata;
 *   ngx_http_mp4_range_t   range;
 * 
 *   ngx_http_mp4_file_t mp4;
 *   ngx_memzero(&mp4, sizeof(ngx_http_mp4_file_t));
 *   mp4.slice_size = NGX_HTTP_MP4_SLICE_SIZE;
 *   mp4.seek_directed = NGX_HTTP_MP4_SEEK_LEFT_DIRECTED;
 *   mp4.file.log = r->connection->log;
 *   mp4.file.name.data = (u_char *)"mp4_body";
 *   mp4.file.name.len = 8;
 *   mp4.start = (ngx_uint_t)start;
 *   mp4.length = length;
 *   mp4.request = r;
 * 
 *   mp4.buffer_start = buf->pos;
 *   mp4.buffer_pos = buf->pos;
 *   mp4.buffer_end = buf->end;
 *   mp4.end = buf->end - buf->pos;
 *  
 *   rc = ngx_http_mp4_process_metadata(r, &mp4, &range);
*/
ngx_int_t ngx_http_mp4_process_metadata(ngx_http_request_t *r,  ngx_http_mp4_file_t  *mp4, ngx_http_mp4_range_t *range);

#endif