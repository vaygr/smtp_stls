-- Enable STARTTLS support for SMTP

local smtp = require("socket.smtp")
local socket = require("socket")
local ssl = require("ssl")

local _M = smtp
local metat = { __index = {} }

function metat.__index:starttls(starttls, domain, params, ext)
  if not domain or not starttls then return 1 end

  -- enforce client mode
  params.mode = "client"
  -- fallback protocol
  params.protocol = params.protocol or "any"

  if string.find(ext, "STARTTLS") then
    self.try(self.tp:command("STARTTLS"))
    self.try(self.tp:check("2.."))
    self.tp.c = self.try(ssl.wrap(self.tp.c, params))
    self.try(self.tp.c:dohandshake())
    -- resend EHLO on success
    self.try(self.tp:command("EHLO", domain))
    return socket.skip(1, self.try(self.tp:check("2..")))
  else
    self.try(nil, "STARTTLS not supported")
  end
end

-- override original socket.smtp.send to inject STARTTLS
_M.send = socket.protect(function(ms)
  local s = _M.open(ms.server, ms.port, ms.create)
  local ext = s:greet(ms.domain)

  local mt = getmetatable(s)
  for k,v in pairs(metat.__index) do mt.__index[k] = v end

  ext = s:starttls(ms.starttls, ms.domain, ms.tls_params, ext)

  s:auth(ms.user, ms.password, ext)
  s:send(ms)
  s:quit()
  return s:close()
end)

return _M
