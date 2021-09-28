description = [[
This script extracts service banners, sysdescr and sysobjectid OID values 
and HTTP(S) responses from the target hosts.
]]

---
-- @usage
-- nmap -sSU -p U:161,T:- --top-ports 1000 --script iotvas-features.nse -Pn <target>


author = "Behrang Fouladi, Firmalyzer BV"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local http = require "http"
local snmp = require "snmp"
local comm = require "comm"
local stdnse = require "stdnse"
local ftp = require "ftp"
local strbuf = require "strbuf"
local tab = require "tab"
local upnp = require "upnp"

hostrule = function(host)
  return true
end

local function get_http_response(host, port)
  local options = { no_cache = true, bypass_cache = true, redirect_ok=function(host, port)
      local c = 5
      return function(url)
        if (c == 0) then return false end
        c = c - 1
        return true
      end
    end }
  local response = http.get(host, port, "/", options)
  if response.body then
    return response.body
  end
  return ""
end

local function get_https_response(host, port)
  local socket, result = comm.tryssl(host, port,("GET / HTTP/1.1\r\nHost: %s\r\n\r\n"):format(stdnse.get_hostname(host)))
  if socket then
    socket:close()
    return ""
  end
  if type(result) == "string" then
    return result
  else
    return ""
  end
end

local function get_ftp_banner(host, port)
  local socket, code, message, buffer = ftp.connect(host, port)
  if not socket then
    return
  end
  socket:close()
  return message
end

local function get_snmp_oid(host, port, oid)
  local options = { timeout = 2000 }
  local snmpHelper = snmp.Helper:new(host, port, "public", options)
  snmpHelper:connect()
  local status, response = snmpHelper:get({reqId=35426}, oid)
  if not status then
    return ("")
  end
  return (response and response[1] and response[1][1])
end

local function get_upnp_response(host)
  local port = { number = 1900, protocol = "udp" }
  local helper = upnp.Helper:new( host, port )
  helper:setOverride( true )
  local status, result = helper:queryServices()
  if ( status ) then
    result["name"] = nil
    return stdnse.format_output(true, result)
  end
end

local function parse_telnet_msg(msg)
  local len = msg:len()
  local opt_type, opt_code, loc
  local out_buf = strbuf.new()
  local got_data = false

  loc = 1
  while loc < (len - 3) do
    if string.byte(msg, loc) == 255 then
      opt_type = string.byte(msg, loc+1)
      opt_code = string.byte(msg, loc+2)
      stdnse.debug("telnet command code received " .. opt_type .. " " .. opt_code)
      if opt_type == 252 and (opt_code == 1 or opt_code == 3) then
        out_buf = out_buf .. string.char(255, 254, opt_code)
      elseif opt_type == 251 and (opt_code == 1 or opt_code == 3) then
        out_buf = out_buf .. string.char(255, 253, opt_code)
      elseif opt_type == 253 then
        out_buf = out_buf .. string.char(255, 252, opt_code)
      else
        stdnse.debug("unhandled telnet command " .. opt_type .. " " .. opt_code)
      end
    else 
      got_data = true
      break
    end
    loc = loc + 3
  end
  return got_data, loc, out_buf
end

local function negotiate_telnet(socket)
  local counter = 0
  local index = 0
  local data = ""
  local status, msg, opt_type, opt_code, data_loc
  local got_data = false

  while true do
    status, msg = socket:receive()
    if not status or msg:len() < 3 then
      stdnse.debug("telnet:no data received")
      break
    end
    got_data, data_loc, out_buf = parse_telnet_msg(msg)
    if got_data then
      data = string.sub(msg, data_loc)
      break
    else
      local reply = strbuf.dump(out_buf)
      if reply:len() > 0 then
        socket:send(reply)
        stdnse.debug("telnet reply size: " .. reply:len())
      end
    end
    counter = counter + 1
    if counter >= 10 then
      break
    end 
  end
  return data
end

local function get_telnet_banner(host, port)
  local socket = nmap.new_socket() 
  socket:set_timeout(2000)
  local st = socket:connect(host, port, 'tcp')
  if not st then
    return
  end
  local data = negotiate_telnet(socket)
  socket:close()
  return data
end

local function is_http_service(name)
  web_services = {
    'http', 'websocket', 'daap',
    'hnap','ipp','soap', 'vnc-http',
    'xml-rpc', 'webdav', 'ws-discovery',
    'http-proxy-ctrl', 'http-proxy'
  }
  for _, item in ipairs(web_services) do
    if item == name then
      return true
    end
  end
  return false
end

host_action = function(host)

  local features = {
    http_response = "",
    https_response = "",
    ftp_banner = "",
    snmp_sysdescr = "",
    snmp_sysoid = "",
    telnet_banner = "",
    hostname = "",
    nic_mac = "",
    upnp_response = ""
  }

 local response = stdnse.output_table()
  local port = nmap.get_ports(host, nil, "tcp", "open")

  if host.mac_addr then
    features.nic_mac = stdnse.format_mac(host.mac_addr)
  end
  if host.name and not string.find(host.name, ".") then
    features.hostname = host.name
  end

  -- get tcp service banners
  while port do
    if port.service then
      if is_http_service(port.service) then
        features.http_response = get_http_response(host, port)

      elseif port.service == 'ssl/http' or port.service == 'https' then
        features.https_response = get_https_response(host, port)

      elseif port.service == 'ftp' or port.service == 'ftp-proxy' then
        features.ftp_banner = get_ftp_banner(host, port)

      elseif port.service == 'telnet' or port.service == 'telnet-proxy' then
        features.telnet_banner = get_telnet_banner(host, port)
      end

    else
        if port.number == 80 then
          features.http_response = get_http_response(host, port)

        elseif port.number == 443 then
          features.https_response = get_https_response(host, port)
        
        elseif port.number == 21 then
          features.ftp_banner = get_ftp_banner(host, port)

        elseif port.number == 23 then
          features.telnet_banner = get_telnet_banner(host, port)
        end
    end 
    port = nmap.get_ports(host, port, "tcp", "open")
  end

  -- get snmp strings
  local snmp_port = nmap.get_port_state(host, {number = 161, protocol = "udp"})
  if snmp_port ~= nil and (snmp_port.state == "open" or snmp_port.state == "open|filtered") then
    features.snmp_sysdescr = get_snmp_oid(host, snmp_port, "1.3.6.1.2.1.1.1.0")
    local oid = get_snmp_oid(host, snmp_port, "1.3.6.1.2.1.1.2.0")
    if oid ~= "" and oid ~=nil then features.snmp_sysoid = snmp.oid2str(oid) end
  end
  -- get upnp response
  features.upnp_response = get_upnp_response(host)

  response["features"] = features
  return response

end


local action_table = {
  hostrule = host_action,
}
action = function(...) return action_table[SCRIPT_TYPE](...) end