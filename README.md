# mp4_vod
nginx mp4 vod module
example conf
```
location / {
	access_by_lua_block {
                        local args = ngx.req.get_uri_args()

                        if args['start'] ~= nil then
                                ngx.var.vdn_vod_seek_start = args['start']
                        end
                        if args['end'] ~= nil then
                                ngx.var.vdn_vod_seek_end = args['end']
                        end
                        if args['preview'] ~= nil then
                                ngx.var.vdn_vod_preview = args['preview']
                        end
                        if args['type'] ~= nil then
                                ngx.var.vdn_vod_seek_type = args['type']
                        end
                }  
                mp4_plus;
                slice_plus 1m;
                slice_plus_buffer_size 2m;
                slice_plus_max_buffer_size 10m;
                proxy_set_header Range $slice_plus_range;
                proxy_set_header If-Range "";
                proxy_pass http://10.211.55.8:8080; 
}
```
