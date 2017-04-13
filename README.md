#   Name

lua-pipe-http

#   Status

It is deployed in a production envinroment

#   Description

Pure lua implementation HTTP pipelining, it base on [lua-pipe](https://github.com/baishancloud/lua-pipe), [lua-acid](https://github.com/baishancloud/lua-pipe)

#   Synopsis

```lua

local pipe_http_put = require("pipe_http.put")

local headers  = ngx.req.get_headers()
local size = tonumber(headers['Content-Length'])

local pipe_http_put, err_code, err_msg = pipe_http_put:new( size )
if err_code ~= nil then
    return nil, err_code, err_msg
end

local dests = {
    {ips={'127.0.0.1'}, port=80, method='PUT', uri='/test1'},
    {ips={'127.0.0.1'}, port=80, method='PUT', uri='/test2'},
    {ips={'127.0.0.1'}, port=80, method='PUT', uri='/test3'},
}

local opts =  {
      quorum = #dests,
      send_timeout = 60000,
      get_existed_file = function() return nil end,
      signature_cb = function(req) return req end,
  }

return pipe_http_put:do_pipe(size, dests, opts)

```
# modules

#   Author

Wu Yipu (吴义谱) <pengsven@gmail.com>

#   Copyright and License

The MIT License (MIT)

Copyright (c) 2017 Wu Yipu (吴义谱) <pengsven@gmail.com>




