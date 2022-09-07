LibDeflate = require("LibDeflate")

local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

saml_protocol = Proto("SAML",  "SAML Protocol")

-- Creamos los campos
local f_request_method = ProtoField.string("SAML.method", "HTTP Method")
local f_request_uri = ProtoField.string("SAML.uri", "HTTP Request URI")
local f_response_code = ProtoField.string("SAML.response.code", "HTTP Response Code")
local f_location = ProtoField.string("SAML.location", "HTTP Location")
local f_data = ProtoField.string("SAML.data", "HTTP File Data")

-- Añadimos los campos al protocolo SAML
saml_protocol.fields = {f_request_method, f_request_uri, f_response_code, f_location, f_tcp}

local f_http_request_method = Field.new("http.request.method")
local f_http_response_code = Field.new("http.response.code")
local f_http_request_uri = Field.new("http.request.uri")
local f_http_location = Field.new("http.location")
local f_http_content_type = Field.new("http.content_type")
local f_http_data = Field.new("http.file_data")
local f_http2_headers_data = Field.new("http2.data.data")
local f_http2_content_type = Field.new("http2.headers.content_type")

function hex2string(hex)
  local str, n = hex:gsub("(%x%x)[ ]?", function (word)
      return string.char(tonumber(word, 16))
  end)
  return str
end

function string2hex (s)
  local hex = "";
  for i=1, #s, 1 do
      hex = hex .. string.format("%x", s:byte(i))
  end
  return hex
end

function dec(data)
  data = string.gsub(data, '[^'..b..'=]', '')
  return (data:gsub('.', function(x)
      if (x == '=') then return '' end
      local r,f='',(b:find(x)-1)
      for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
      return r;
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
      if (#x ~= 8) then return '' end
      local c=0
      for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
          return string.char(c)
  end))
end

function urldecode(s)
  s = s:gsub('+', ' ')
       :gsub('%%(%x%x)', function(h)
                           return string.char(tonumber(h, 16))
                         end)
  return s
end

function parseURL(string_URL, f_subtree)

  string_URL = string_URL:match('%s+(.+)')
  if string_URL then

    for v in string_URL:gmatch('([^&=?]-)=([^&=?]+)' ) do
      f_subtree:add(f_request_uri, urldecode(v))
      --ans[ k ] = urldecode(v)
    end
  end
  --return ans

end

function saml_protocol.dissector(buffer, pinfo, tree)

	local http_request_method = f_http_request_method()
  local http_request_uri = f_http_request_uri()
	local http_response_code = f_http_response_code()
  local http_location = f_http_location()
  local http_content_type = f_http_content_type()
  local http_data = f_http_data()
  local http2_headers_data = f_http2_headers_data()
  local http2_content_type = f_http2_content_type()
  
  local content = nil
  local iStart = 0
  local iEnd = 0

  if http_request_method then
    if http_request_method.value == "GET" then
      if http_request_uri then
       
        content = http_request_uri.value

        iStart = string.find(content:upper(),"SAMLREQUEST")
        if not(iStart == nil) then

          iStart = string.find(content,"?")
          if not(iStart == nil) then
  
            iEnd = string.find(content,"&")

            local query = string.sub(content, iStart + 1, iEnd - 1)
  
            iStart = string.find(query,"=")
            query = string.sub(query, iStart + 1, iEnd)
  
            query = urldecode(query)
            query = dec(query)
            query = LibDeflate:DecompressDeflate(query)
            if not(query==nil) then

              pinfo.cols.protocol = saml_protocol.name
              local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
             
              subtree:add(f_request_uri, content)

              query = string.gsub(query, "\" ", "\"\n\t\t\t\t")
              query = string.gsub(query, " ", "\t")
              query = string.gsub(query, "><", "> \n \t \t<")
              subtree:add("SAML Request:       ", query)

              query = string.sub(content, iEnd + 1)
              iStart = string.find(query,"=")
              query = string.sub(query, iStart + 1)
              query = urldecode(query)
              subtree:add("SAML Request (Relay State):       ", query)
            end
          end
        end

        iStart = string.find(content:upper(),"SAMLART")
        if not(iStart == nil) then

          iStart = string.find(content,"?")
          if not(iStart == nil) then
  
            iEnd = string.find(content,"&")

            local query = string.sub(content, iStart + 1, iEnd - 1)
  
            iStart = string.find(query,"=")
            query = string.sub(query, iStart + 1, iEnd)
  
            query = urldecode(query)
            query = dec(query)
  
            query = LibDeflate:DecompressDeflate(query)
            if not(query==nil) then

              pinfo.cols.protocol = saml_protocol.name
              local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
             
              subtree:add(f_request_uri, content)

              query = string.gsub(query, "\" ", "\"\n\t\t\t\t")
              query = string.gsub(query, " ", "\t")
              query = string.gsub(query, "><", "> \n \t \t<")
              subtree:add("SAML Artifact:       ", query)

            end
          end
        end

      end

    elseif http_request_method.value == "POST" then
        
        if http_content_type.value == "application/x-www-form-urlencoded" then
          if http_data then
            local data = http_data.value
            iStart = string.find(data:upper(),"SAMLREQUEST")
            if not(iStart == nil) then
              -- Tenemos el SAMLRequest
              iStart = string.find(data,"=")
              iEnd = string.find(data,"&")
              if iEnd == nil then
                data = string.sub(data, iStart + 1)
              else
                data = string.sub(data, iStart + 1, iEnd - 1)
              end
      
              data = urldecode(data)
              data = dec(data)
              data = string.gsub(data, "\" ", "\"\n\t\t\t\t")
              data = string.gsub(data, " ", "\t")
              data = string.gsub(data, "><", "> \n \t \t<")
    
              pinfo.cols.protocol = saml_protocol.name
              local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
                
              subtree:add("DATA:       ", data)
              if not(iEnd == nil) then
                data = http_data.value
                data = string.sub(data, iEnd + 1)
                iStart = string.find(data,"=")
                data = string.sub(data, iStart + 1)
                data = urldecode(data)
    
                subtree:add("DATA (relay):       ", data)
              end
  
            else
              iStart = string.find(data:upper(),"SAMLRESPONSE")
              if not(iStart == nil) then
                            -- Tenemos el SAMLResponse
                iStart = string.find(data,"=")
                iEnd = string.find(data,"&")
                if iEnd == 0 then
                  data = string.sub(data, iStart + 1)
                else
                  data = string.sub(data, iStart + 1, iEnd)
                end
        
                data = urldecode(data)
                data = dec(data)
                data = string.gsub(data, "\" ", "\"\n\t\t\t\t")
                data = string.gsub(data, " ", "\t")
                data = string.gsub(data, "><", "> \n \t \t<")
      
                pinfo.cols.protocol = saml_protocol.name
                local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
                  
                subtree:add("DATA:       ", data)
  
                data = http_data.value
                iStart = string.find(data:upper(),"RELAYSTATE")
                if not(iStart == nil) then
                  data = string.sub(data, iStart)
  
                  iStart = string.find(data,"=")
                  iEnd = string.find(data,"&")
                  if iEnd == 0 then
                    data = string.sub(data, iStart + 1)
                  else
                    data = string.sub(data, iStart + 1, iEnd)
                  end
  
                  --data = string.sub(data, iEnd + 1)
                  --iStart = string.find(data,"=")
                  --data = string.sub(data, iStart + 1)
                  data = urldecode(data)
    
                  subtree:add("DATA (relay):       ", data)
  
                end
              end
            end
          end
        end

    end
  end



  if http2_headers_data then
      
      content = hex2string(http2_headers_data.label)
      content = string.gsub(content, ":", "")
      iStart = string.find(content:upper(),"SAMLRESPONSE=")
      if not(iStart == nil) then

        iStart = string.find(content,"=")
        iEnd = string.find(content,"&")
        if iEnd == 0 then
          content = string.sub(content, iStart + 1)
        else
          content = string.sub(content, iStart + 1, iEnd)
        end

        content = urldecode(content)
        content = dec(content)
        content = string.gsub(content, "\" ", "\"\n\t\t\t\t")
        content = string.gsub(content, " ", "\t")
        content = string.gsub(content, "><", "> \n \t \t<")
    
        pinfo.cols.protocol = saml_protocol.name
        local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
        
        subtree:add("DATA SAML Response:       ", content)

        content = hex2string(http2_headers_data.label)
        content = string.gsub(content, ":", "")
        iStart = string.find(content:upper(),"TARGET")
        if not(iStart == nil) then
          content = string.sub(content, iStart)
  
          iStart = string.find(content,"=")
          iEnd = string.find(content,"&")
          if iEnd == 0 then
            content = string.sub(content, iStart + 1)
          else
            content = string.sub(content, iStart + 1, iEnd)
          end

          content = urldecode(content)

          subtree:add("DATA (TARGET):       ", content)
  
        end

      end

  end

  if http_response_code then
    if http_response_code.value == 302 or http_response_code.value == 303 then
      if http_location then
        content = http_location.value

        iStart = string.find(content:upper(),"SAMLREQUEST=")
        if not(iStart == nil) then
  
          iStart = string.find(content,"=")
          iEnd = string.find(content,"&")
          if iEnd == nil then
            content = string.sub(content, iStart + 1)
          else
            content = string.sub(content, iStart + 1, iEnd - 1)
          end

          content = urldecode(content)
          content = dec(content)

          content = LibDeflate:DecompressDeflate(content)
          if not(content == nil) then
            content = string.gsub(content, "\" ", "\"\n\t\t\t\t")
            content = string.gsub(content, " ", "\t")
            content = string.gsub(content, "><", "> \n \t \t<")

            pinfo.cols.protocol = saml_protocol.name
            local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
          
            subtree:add("LOCATION WITH SAMLRequest:       ", content)
          end
        end

        content = http_location.value
        iStart = string.find(content:upper(),"SAMLART=")
        if not(iStart == nil) then
  
          iStart = string.find(content,"=")
          iEnd = string.find(content,"&")
          if iEnd == nil then
            content = string.sub(content, iStart + 1)
          else
            content = string.sub(content, iStart + 1, iEnd - 1)
          end

          content = urldecode(content)

          pinfo.cols.protocol = saml_protocol.name
          local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
        
          subtree:add("LOCATION WITH SAMLArtifact:       ", content)
          
        end

      end
    end

    if http_response_code.value == 200 then

          if http_request_uri then
       
            content = http_request_uri.value
    
            iStart = string.find(content:upper(),"SAMLREQUEST")
            if not(iStart == nil) then
    
              iStart = string.find(content,"?")
              if not(iStart == nil) then
      
                iEnd = string.find(content,"&")
    
                local query = string.sub(content, iStart + 1, iEnd - 1)
      
                iStart = string.find(query,"=")
                query = string.sub(query, iStart + 1, iEnd)
      
                query = urldecode(query)
                query = dec(query)
                query = LibDeflate:DecompressDeflate(query)
                if not(query==nil) then
    
                  pinfo.cols.protocol = saml_protocol.name
                  local subtree = tree:add(saml_protocol, buffer(), "SAML Protocol Data")
                 
                  subtree:add(f_request_uri, content)
    
                  query = string.gsub(query, "\" ", "\"\n\t\t\t\t")
                  query = string.gsub(query, " ", "\t")
                  query = string.gsub(query, "><", "> \n \t \t<")
                  subtree:add("SAML Request:       ", query)
    
                  query = string.sub(content, iEnd + 1)
                  iStart = string.find(query,"=")
                  query = string.sub(query, iStart + 1)
                  query = urldecode(query)
                  subtree:add("SAML Request (Relay State):       ", query)
                end
              end
            end

      end
    end
  end

end


register_postdissector(saml_protocol)