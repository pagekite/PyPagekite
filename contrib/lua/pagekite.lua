#!/usr/bin/lua

--
-- Pagekite(.net) back-end client in Lua
-- by Stelios Mersinas (steliosm@gmail.com)
-- v0.3
--

-- 
-- Changelog:
--
-- 0.3
-- Supports tunnel status check using PING packets.
-- A start.sh scripts re-starts the service if needed
--

-- Load the needed modules
require "socket"
require "os"
require "math"

-- load the SHA1 encryption library
dofile "lib/shalib.lua"

--
-- Read the config file
--
dofile ".config"

--
-- Functions Part
--

function string.trim(str)
  return (string.gsub(str, "^%s*(.-)%s*$", "%1"))
end


function string.explode(str, sep)
  -- Split a string based on sep value.
  -- Return a table back
  local pos, t = 1, {}
  if #sep == 0 or #str == 0 then return end
  for s, e in function() return string.find(str, sep, pos) end do
    table.insert(t, string.trim(string.sub(str, pos, s-1)))
    pos = e+1
  end
  table.insert(t, string.trim(string.sub(str, pos)))
  return t
end


function sleep (my_sec)
  -- A function to make Lua sleep for a bit :-)
  -- It's an ugly hack actually.
  os.execute("sleep " .. tonumber(my_sec))
end

function ConnectToServer (my_server, my_port)
  -- Create a socket and connect to server/port given.
  -- In case of a connection problem, conn will be nil and status will hold the error message
  local conn, status = socket.connect (my_server, my_port)

  -- Check weather we got a connection to set the timeout option
  if conn then
    -- Set a socket timeout value. This will allow us to skip blobking for ever on socket:receive()
    conn:settimeout (30)
  end
  
  -- Return the socket object
  return conn, status
end


function PingServer (fe_socket)
  -- Do a PING request to the server to check if the tunnel is up.
  -- The server should response with a NOOP header.
  -- In case the connection is down, then the socket:receive() will timeout

  if debug then print ( os.date("%c"), "[PingServer] Ping?") end
  local ping = false

  -- Build the Ping frame request
  local my_chunk = "NOOP: 1\r\nPING: 1\r\n\r\n!"
  local my_chunk_length = string.len(my_chunk)
  local my_frame = string.format ("%x", my_chunk_length) .. "\r\n" .. my_chunk

  -- Send the Ping request to the server
  fe_socket:send ( my_frame )

  -- Listen for the reply
  frame_header, status, partial = fe_socket:receive("*l")

  if frame_header ~= nil then
    -- Socket didn't timeout, the connection seems to be alive.
    -- Read the rest of the frame data and look for a NOOP reply
    local frame_size = tonumber (frame_header, 16)
    local frame_data, status, partial = fe_socket:receive (frame_size)

    -- Check for the NOOP header
    if string.find ( frame_data, "NOOP") then
      if debug then print ( os.date("%c"), "[PingServer] Pong!") end
      ping = true
    end
  else
    ping = false
  end

  -- Return the result
  return ping
end


function PhaseOne ()
  --
  -- Make a connection to PageKite server and send a challenge request.
  -- This is the first phase of the authecation handshakng procedure.
  --

  -- Define the variable to hold the server's response
  local my_challenge_string, my_session_id = ""

  -- Generate a random string using the math.random() functionstring.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 )
  -- and cut a 36-bytes long string for the BSalt field and a 8 byte long string for the salt.
  math.randomseed ( os.time() )
  local my_random_bsalt =  string.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ), 1, 36)
  local my_random_salt = string.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ), 1, 8)

  -- Sign the data string (Sig) using the shared secret contained in the .config file
  local my_data = string.format ("http:%s:%s", pk_site, my_random_bsalt)
  --local my_signed_string = string.sub("87654321" .. sha1(pk_server_token .. my_data .. ":87654321"), 1, 36)
  local my_signed_string = string.sub(my_random_salt .. sha1(pk_server_token .. my_data .. ":" .. my_random_salt), 1, 36)

  -- Create the Phase-One authentication request
  local my_request = "CONNECT PageKite:1 HTTP/1.0\r\n" .. "X-PageKite-Version: 0.3.21\r\n" ..
  string.format ( "X-PageKite: http:%s:%s::%s", pk_site, my_random_bsalt, my_signed_string ) .. "\r\n\r\n"

  -- Make a connection to the Front-end server
  local remote_conn, error = ConnectToServer (pk_server, pk_server_port)

  -- Check if the connection was sucessful
  if remote_conn then
    -- We have a connection, send the authentication string
    remote_conn:send ( my_request )

    -- Read the response for the server. Look for the challenge header
    while true do
      local data, status, partial = remote_conn:receive ("*l")
      -- Check if the remote port is closed
      if status == "closed" then break end

      -- Check for the challenge header
      if data ~= "" then
        header = string.explode(data, ":")

        -- Look for the Challenge request
        if header[1] == "X-PageKite-SignThis" then
          -- Challenge string found
          my_challenge_string = string.sub(data,22)
        end

        -- Look for the Session ID
        if header[1] == "X-PageKite-SessionID" then
          -- Session ID header found
          my_session_id = string.sub(data,23)
        end
      end
    end

    -- Close the socket - should already be closed by the server
    remote_conn:close()

    -- Return the values back
    return my_challenge_string, my_session_id

  else
    -- Error connecting to remote server. Return nil and the error message
    return nil, error
  end

end


function PhaseTwo (my_challenge_header, my_session_id)
  --
  -- Reply to the challenge request and setup the tunnel
  --

  -- Create challenge reply
  local my_random_salt = string.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ), 1, 8)
  local my_challenge_reply = my_random_salt .. sha1 (pk_server_token .. my_challenge_header .. my_random_salt)

  -- Build the response
  local my_challenge_response = "CONNECT PageKite:1 HTTP/1.0\r\n" .. "X-PageKite-Version: 0.3.21\r\n" ..
  string.format ("X-PageKite-Replace: %s", my_session_id) .. "\r\n" ..
  string.format ("X-PageKite: %s:%s", my_challenge_header, string.sub(my_challenge_reply,1,36)) .. "\r\n\r\n"

  -- Connect to the server and send the reply back
  local remote_conn, error = ConnectToServer (pk_server, pk_server_port)

  -- Check if got connected and send the reply back
  if remote_conn then
    -- Send the response back
    remote_conn:send ( my_challenge_response )

    -- Read the response for the server. Look for the OK header
    while true do
      data, status, partial = remote_conn:receive ("*l")
      -- Check if the remote port is closed
      if status == "closed" then break end
      if data ~= "" then
        header = string.explode(data, ":")
      end
      if header[1] == "X-PageKite-OK" then
        -- OK header found, set a flag
        ok_flag = 1
      end
      if data == "" and ok_flag == 1 then
        -- Final line, exit the loop
        break
      end
    end

    -- Tunnel is configured, return the socket object.
    return remote_conn
  else
    -- Problem connecting to server and setting up the tunnel.
    -- Send a nil value and the error message.
    return nil, error
  end
end


function HTTP_handler ( my_chunk )
  -- Make an HTTP request to the server, push the data and get a reply back

  local http_reply, http_conn
  local remote_conn, error = ConnectToServer (proxy_web, proxy_web_port)
  if debug then print (os.date("%c"), "[HTTP Response] Making Proxy connection to web server") end

  -- Check if we got connected to the web server
  if remote_conn then
    -- We have a connection, send the request
    remote_conn:send(my_chunk)
    remote_conn:send("\r\n")

    -- Get the reply back from the web server
    -- Note: Busyboxe's httpd server supports HTTP/0.9, so the connection closes after each request.
    http_reply = remote_conn:receive("*a")
  else
    -- Problem connecting, send error message back
    http_reply = nil
  end

  -- Return the data
  return http_reply
end


function RequestHandler ( my_frame_data )
  -- Parse the frame and send a reply back
--  -- Find out the request type (currently only HTTP requests are supported)

  local chunk, frame_length, frame_response, session_id
  local http_request = ""
  local protocol_response, request_is_http

  for request_line in my_frame_data:gmatch("[^\r\n]+") do
    -- Look for the SID header to get the size of data comming
    if string.find (request_line, "SID:") then
      -- Get the SID and store it
      frame_header = string.explode(request_line, ":")
      session_id = frame_header[2]
    end

    -- Check if this is an HTTP request
    if string.find (request_line, "GET /") then
      request_is_http = true
     -- http_request = request_line
    end

    -- Add the HTTP headers to a buffer
    if request_is_http then
      if request_line == "" then
        request_line = "\r\n"
      end
      http_request = http_request .. request_line .. "\r\n"
    end

  -- End For loop
  end

  -- Call the protocol handler
  if request_is_http ~= nil then
    -- Call the HTTP handler
    if debug then print (os.date("%c"), "[RequestHandler] Calling HTTP Response handler") end
    protocol_response = HTTP_handler ( http_request )
  else
    if debug then print (os.date("%c"), "[RequestHandler] Request type is UNKNOWN ") end
    protocol_response = nil
  end

  -- Check if we got a response back
  if protocol_response ~= nil then
    -- Create the response frame
    chunk = "SID: " .. session_id .. "\r\n" .. "\r\n" .. protocol_response

    -- Calculate frame size
    frame_length = string.len (chunk)
    frame_response = string.format ("%x",frame_length) .. "\r\n" .. chunk

    -- Create the EOF chunk as well
    eof_chunk = "SID: " .. session_id .. "\r\n" .. "EOF: RW" .. "\r\n\r\n"
    eof_length = string.len (eof_chunk)
    eof_frame = string.format ("%x", eof_length) .. "\r\n" .. eof_chunk

    frame_response = frame_response .. eof_frame

  else
    -- Send an empty frame
    frame_response = nil
  end

  -- Send the frame back
  return frame_response
end


function PageKite ( fe_socket )
  -- This is the protocol handler.
  -- It's responsible to receive and send data over the network connection.

  local frame_size, frame_data, frame_response

  -- Start a big loop - look for frames arriving or for a closed remote connection
  if debug then print ( os.date("%c"), "[PageKite] Waitting for data...") end
  while true do
    -- Loop over the socket and keep reading data until it closes
    -- The first line should contain the frame size
    local frame_header, status, partial = fe_socket:receive ("*l")

    if status == "closed" then
      -- Remote peer closed the connection!
      if debug then print (os.date("%c"), "[PageKite] Remote connection closed! Exiting...") end
      break
    end

    if status == "timeout" then
      -- Do a ping to the server to check the link status
      if not PingServer ( fe_socket ) then break end
    end

    if frame_header ~= nil then
      -- Get the first line of the frame. This should be the size of the chunk.
      frame_size = tonumber(frame_header, 16)
      if debug then print (os.date("%c"), "[PageKite] Incoming frame " .. frame_size .. " (0x" .. frame_header ..") bytes long") end

      -- Read the rest of the request to a buffer
      frame_data, status, partial = fe_socket:receive (frame_size)

      -- Call the Request Handler and get back a frame to send to the server
      if debug then print (os.date("%c"), "[PageKite] Calling RequestHandler") end
      frame_response = RequestHandler (frame_data)

      -- Send the request back to the front end
      -- If there is no response frame do not send anything
      if frame_response ~= nil then
        if debug then print (os.date("%c"), "[PageKite] Sending reply to FrontEnd") end
        fe_socket:send ( frame_response )
      end

    end

  end

end


--
-- Main Part
--

-- Run at least once and loop only if the user has defined server_reconnect as true.
repeat

  -- Start PhaseOne authentication process
  -- Get the challenge response back to proceed to the second phase.
  challenge, session_id = PhaseOne ()

  -- Check if we have a challenge string.
  if challenge then
    -- Phase One was completed successful. Move to phase 2
    remote_conn, error = PhaseTwo (challenge, session_id)

    -- Check if we passed Phase Two authentication
    if remote_conn then
      -- Authenticated with server.
      print ("Ready.")
      -- Get the PageKite protocol handler
      PageKite (remote_conn)
    else
      -- Couldn't connect to remote server
      print ("Error connecting to remote server: " .. error)
    end
  end

  -- Try to reconnect to server after sleeping for 10 seconds
  if debug then print (os.date("%c"), "Reconnecting to server...") end
  
  -- Make a small pause before reconnecting to the server
  sleep (10)
  
-- Loop over
until server_reconnect == 0

