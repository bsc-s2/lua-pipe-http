local strutil = require("acid.strutil")
local resty_string = require("resty.string")
local resty_sha1 = require("resty.sha1")
local resty_md5 = require("resty.md5")
local acid_json = require("acid.json")
local form_multipart = require("form_multipart")
local resty_upload = require("resty.upload")

local pipe_pipe = require("pipe.pipe")

local ngx_abort = require("acid.ngx_abort")

local _M = {}
local mt = { __index = _M }

local to_str = strutil.to_str

local BLOCK_SIZE = 1024*1024
local SOCKET_TIMEOUT = 100 * 1000

local CRLF = '\r\n'
local FIELD_END = CRLF

_M.STAT_BEGIN = 1
_M.STAT_READ_HEADER = 2
_M.STAT_READ_FILE_BODY = 3
_M.STAT_EOF = 4

local function update_checksum( self, recv_data )

    if self.alg_md5 ~= nil then
        self.alg_md5:update(recv_data)
    end

    if self.alg_sha1 ~= nil then
        self.alg_sha1:update(recv_data)
    end
end

local function make_file_field_headers( self, file_headers )
    return '--'.. self.boundary .. CRLF
            .. table.concat( file_headers, CRLF ) .. CRLF
            .. CRLF
end

local function get_last_padding_body(self, padding_size)

    local boundary = '--' .. self.boundary
    local last_boundary = boundary .. '--'

    if padding_size < #last_boundary + #CRLF then
        return nil, 'InternalError', 'send body size less than last boundary size'
    elseif padding_size == #last_boundary + #CRLF then
        return last_boundary .. CRLF
    end

    local padding_data = {
        boundary,
        'Content-Disposition: form-data; name="pading"',
        ''}

    local padding_val_size = padding_size
        - string.len(table.concat(padding_data, CRLF))
        - #CRLF
        -- value size
        - #CRLF
        - #last_boundary
        - #CRLF

    if padding_val_size < 0 then
        return nil, 'InternalError', 'last padding feild body size less than 0'
    end

    table.insert(padding_data, string.rep("x", padding_val_size))
    table.insert(padding_data, last_boundary)
    table.insert(padding_data, '')

    return table.concat(padding_data, CRLF)
end

local function make_pipe_form_file_filter(self, pipe_size)
    local dest_sess = self.dest_sess
    local alg_sha1  = resty_sha1:new()

    local send_size = 0

    return function(rbufs, n_rd, wbufs, n_wrt, pipe_rst)
        local recv_data = rbufs[1]

        if recv_data == '' then
            for i = 1, n_wrt do
                wbufs[i] = recv_data
            end
            return
        end

        local send_data = {}
        if send_size == 0 then
            table.insert(send_data, self.str_file_field_headers)
        end

        if recv_data.type == 'body' then
            alg_sha1:update(recv_data.data)
            update_checksum(self, recv_data.data)

            table.insert(send_data, recv_data.data)
            self.send_file_size = self.send_file_size + #(recv_data.data)
        elseif recv_data.type == 'body_end' or recv_data.type == 'part_end' then
            if recv_data.type == 'part_end' then
                self.stat = _M.STAT_EOF
            end

            dest_sess.recv_file_sha1 = resty_string.to_hex(alg_sha1:final())

            if dest_sess.get_existed_file ~= nil then
                local file_info = dest_sess.get_existed_file(dest_sess.recv_file_sha1)
                if file_info ~= nil then
                    local rst = {
                        status  = 200,
                        headers = {},
                        body    = acid_json.enc(file_info),
                    }
                    return rst, 'InterruptError', 'file already exists'
                end
            end

            table.insert(send_data, FIELD_END)

            local psize = pipe_size - send_size - #(table.concat(send_data, ''))
            local pbody, err_code, err_msg = get_last_padding_body(self, psize)
            if err_code ~= nil then
                return nil, err_code, err_msg
            end
            table.insert(send_data, pbody)
        end

        send_data = table.concat(send_data, '')

        for i = 1, n_wrt do
            wbufs[i] = send_data
        end

        send_size = send_size + #send_data
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

function _M.new(_, total_body_size, opts )
    local opts = opts or {}

    local sess = {
        method = 'POST',

        form = nil,
        recv_timeout = opts.recv_timeout or SOCKET_TIMEOUT,
        block_size   = opts.block_size or BLOCK_SIZE,

        alg_md5   = opts.calc_md5 and resty_md5:new(),
        alg_sha1  = opts.calc_sha1 and resty_sha1:new(),

        post_param = {},

        stat = _M.STAT_BEGIN,

        str_file_field_headers = '',

        send_file_size = 0,
        total_body_size = total_body_size,
    }

    local form_upload, err_msg = resty_upload:new(sess.block_size)
    if not form_upload then
        return nil, 'InvalidRequest', to_str('Request socket ', err_msg)
    end
    form_upload:set_timeout(sess.recv_timeout)
    sess.boundary = form_upload.boundary

    sess.form = form_multipart:new(form_upload)

    return setmetatable(sess, mt)
end

function _M.parse_form_until_file_body(self)
    if self.stat ~= _M.STAT_BEGIN then
        return nil, "InvalidRequest", "file field has been read"
    end

    self.stat = _M.STAT_READ_HEADER

    while true do

        local headers, err_code, err_msg = self.form:read_field_headers()
        if err_code ~= nil then
            return nil, "InvalidRequest", to_str(err_code, ':', err_msg)
        end

        local field_name = headers.field_name

        if field_name == 'file' then
            local val = headers.headers
            val.file_name = headers.file_name
            self.post_param[field_name] = val

            self.str_file_field_headers =
                make_file_field_headers(self, headers.raw_headers)

            self.stat = _M.STAT_READ_FILE_BODY
            break
        end

        local val, err_code, err_msg = self.form:read_field_value(field_name)
        if err_code ~= nil then
            return nil, err_code, err_msg
        end

        self.post_param[ field_name ] = val
    end

    return self.post_param, nil, nil
end

local function make_pipe_form_file_reader(form, size, block_size)
    local ret = {
        size = 0,
        time = 0,
    }
    return function(pobj, ident)
        while true do
            local typ = 'body'

            local read_size = math.min(size, block_size)
            local t0 = ngx.now()
            local buf, err_code, err_msg = form:read_field_value('file', read_size)
            ret.time = ret.time + (ngx.now() - t0)
            if err_code ~= nil then
                return nil, err_code, err_msg
            end

            if buf == '' then
                typ = 'body_end'
                if size > 0 then
                    typ = 'part_end'
                end
            end

            local _, err_code, err_msg = pobj:write_pipe(ident, {['type']=typ, data=buf})
            if err_code ~= nil then
                return nil, err_code, err_msg
            end

            ret.size = ret.size + #buf

            if buf == '' then
                break
            end

            size = size - #buf
        end

        local _, err_code, err_msg = pobj:write_pipe(ident, '')
        if err_code ~= nil then
            return nil, err_code, err_msg
        end

        return ret
    end
end

function _M.do_pipe( self, file_size, dests, opts )
    if self.stat ~= _M.STAT_READ_FILE_BODY then
        return nil, "InvalidRequest", "Form file field format error"
    end

    local dest_sess = set_dests_args(self, dests, opts)

    file_size = math.min(file_size, self.total_body_size - self.send_file_size)

    -- To resume greater than or equal a minimum form-field,
    -- addition of an extra 256 bytes. Minimum form-feild:
    --<boundary>\r\nContent-Disposition: form-data; name="x"\r\n
    local pipe_size = #self.str_file_field_headers + file_size + #FIELD_END + 256

    local readers = {
            make_pipe_form_file_reader(self.form, file_size, self.block_size)
        }

    local wrt_opts = {
            signature_cb = dest_sess.signature_cb,
            timeout = self.send_timeout,
            headers = {
                ['Content-Length'] = pipe_size,
                ['Content-Type'] = 'multipart/form-data; boundary=' .. self.boundary,
            },
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
                make_pipe_form_file_filter(self, pipe_size),
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
        dest_sess.dests[i].err  = rst.err
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
        file_size  = self.send_file_size,
    }
end

function _M.is_eof( self )
    return self.stat == _M.STAT_EOF
end

function _M.get_recv_sha1( self )
    return self.dest_sess.recv_file_sha1
end

return _M
