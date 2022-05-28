# smtp_stls

socket.smtp module with STARTTLS support.

### Dependencies

- [luasocket](https://github.com/lunarmodules/luasocket)
- [luasec](https://github.com/brunoos/luasec)

### Usage

```lua
local smtp = require("smtp_stls")

local function mail(to, subject, message)
  local settings = {
    from = 'from@domain.tld',
    domain = 'localhost',
    -- user = '...',
    -- password = '...',
    server = '127.0.0.1',
    port = 25,
    starttls = true,
    tls_params = {
      mode = "client",
      protocol = "tlsv1_3",
      verify = "peer",
      cafile = "/etc/ssl/certs/ca-certificates.crt",
      options = {"all", "no_sslv3"}
    },
  }

  if type(to) ~= 'table' then
    to = { to }
  end

  for index, email in ipairs(to) do
    to[index] = '<' .. tostring(email) .. '>'
  end

  -- fixup from field
  local from = '<' .. tostring(settings.from) .. '>'

  -- message headers and body
  settings.source = smtp.message({
    headers = {
      to = table.concat(to, ', '),
      subject = subject,
      ['From'] = from,
      ['Content-type'] = 'text/html; charset=utf-8',
    },
    body = message
  })

  settings.from = from
  settings.rcpt = to

  return smtp.send(settings)
end

mail("to@domain.tld", "Subject", "Test letter")
```
