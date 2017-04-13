local strutil = require("acid.strutil")

local resty_string = require( "resty.string" )
local resty_sha1 = require( "resty.sha1" )
local resty_md5  = require( "resty.md5" )
local acid_json = require("acid.json")
local pipe_pipe = require("pipe.pipe")

local ngx_abort = require("acid.ngx_abort")

local _M = { _VERSION = '1.0' }
local mt = { __index = _M }

local to_str = strutil.to_str

local BLOCK_SIZE = 1024*1024
local SOCKET_TIMEOUT = 100 * 1000

local function update_checksum( self, recv_data )
    if self.alg_md5 ~= nil then
        self.alg_md5:update(recv_data)
    end

    if self.alg_sha1 ~= nil then
        self.alg_sha1:update(recv_data)
    end
end

local function set_dests_args(self, dests, opts)
    opts = opts or {}

    self.dest_sess = {
        dests = dests,

        quorum = opts.quorum or #dests,
        send_timeout = opts.send_timeout or SOCKET_TIMEOUT,

        recv_file_sha1   = nil,
        get_existed_file = opts.get_existed_file,

        signature_cb = opts.signature_cb,
   }

    return self.dest_sess
end

function _M.new( _, total_body_size, opts )
    opts = opts or {}

    local sess = {
        method = 'PUT',

        recv_sock = nil,
        recv_timeout = opts.recv_timeout or SOCKET_TIMEOUT,
        block_size   = opts.block_size or BLOCK_SIZE,

        alg_md5   = opts.calc_md5 and resty_md5:new(),
        alg_sha1  = opts.calc_sha1 and resty_sha1:new(),

        send_file_size = 0,
        total_body_size = total_body_size,
    }

    local err_msg
    sess.recv_sock, err_msg = ngx.req.socket()
    if sess.recv_sock == nil then
        return nil, 'InvalidRequest', to_str('Request socket error ', err_msg)
    end
    sess.recv_sock:settimeout( sess.recv_timeout )

    return setmetatable(sess, mt)
end

local function make_pipe_filter(self, file_size)
    local dest_sess = self.dest_sess
    local alg_sha1  = resty_sha1:new()
    local recv_size = 0

    return function(rbufs, n_rd, wbufs, n_wrt, pipe_rst)
        local recv_data = rbufs[1]

        for i = 1, n_wrt do
            wbufs[i] = recv_data
        end

        if recv_data == '' then
            return
        end

        alg_sha1:update(recv_data)
        update_checksum(self, recv_data)

        self.send_file_size = self.send_file_size + #recv_data
        recv_size = recv_size + #recv_data

        if recv_size == file_size then
            dest_sess.recv_file_sha1 = resty_string.to_hex(alg_sha1:final())

            local file_info = nil
            if dest_sess.get_existed_file ~= nil then
                file_info = dest_sess.get_existed_file(dest_sess.recv_file_sha1)
            end

            if file_info ~= nil then
                local rst = {
                    status  = 200,
                    headers = {},
                    body    = acid_json.enc(file_info),
                }
                return rst, 'InterruptError', 'file already exists'
            end
        end
    end
end

function _M.do_pipe(self, file_size, dests, opts)
    local dest_sess = set_dests_args(self, dests, opts)

    file_size = math.min(file_size, self.total_body_size - self.send_file_size)

    local readers = {
            pipe_pipe.reader.make_socket_reader(self.recv_sock, file_size, self.block_size)
        }

    local wrt_opts = {
            signature_cb = dest_sess.signature_cb,
            timeout = self.send_timeout,
            headers = {['Content-Length'] = file_size},
        }

    local writers = {}
    for _, dest in ipairs(dest_sess.dests) do
        local writer = pipe_pipe.writer.make_http_writer(
            dest.ips, dest.port, dest.method, dest.uri, wrt_opts)

       table.insert(writers, writer)
    end

    local filters = {
            rd_filters = {
                pipe_pipe.filter.make_rbufs_not_nil_filter(1),
                make_pipe_filter(self, file_size),
            },
            wrt_filters = {
                pipe_pipe.filter.make_write_quorum_filter(dest_sess.quorum),
            },
        }

    local pipe = pipe_pipe:new(readers, writers, filters)

    local is_running = ngx_abort.install_running()
    local pipe_rst, err_code, err_msg = pipe:pipe(is_running)
    if err_code ~= nil then
        return nil, err_code, err_msg
    end

    local r_rst = pipe_rst.read_result[1].result or {}

    for i, rst in ipairs(pipe_rst.write_result) do
        dest_sess.dests[i].resp = rst.result
        dest_sess.dests[i].err = rst.err
        dest_sess.dests[i].stats = {trecv=r_rst.time}
     end

    return dest_sess.dests
end

function _M.final_checksum(self)
    local md5_sum, sha1_sum

    if self.alg_md5 ~= nil then
        md5_sum = resty_string.to_hex(self.alg_md5:final())
    end
    if self.alg_sha1 ~= nil then
        sha1_sum = resty_string.to_hex(self.alg_sha1:final())
    end

    return {
        file_md5  = md5_sum,
        file_sha1 = sha1_sum,
        file_size = self.send_file_size,
    }
end

function _M.is_eof( self )
    return self.total_body_size == self.send_file_size
end

function _M.get_recv_sha1( self )
    return self.dest_sess.recv_file_sha1
end

return _M
