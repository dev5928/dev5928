local bin = require("bin")
local nmap = require("nmap")
local stdnse = require("stdnse")
local ssl_status,openssl = pcall(require,"openssl")

Capabilities =
{
	LongPassword = 0x1,
	FoundRows = 0x2,
	LongColumnFlag = 0x4,
	ConnectWithDatabase = 0x8,
	DontAllowDatabaseTableColumn = 0x10,
	SupportsCompression = 0x20,
	ODBCClient = 0x40,
	SupportsLoadDataLocal = 0x80,
	IgnoreSpaceBeforeParenthesis = 0x100,
	Speaks41ProtocolNew = 0x200,
	InteractiveClient = 0x400,
	SwitchToSSLAfterHandshake = 0x800,
	IgnoreSigpipes = 0x1000,
	SupportsTransactions = 0x2000,
	Speaks41ProtocolOld = 0x4000,
	Support41Auth = 0x8000,
	SupportsMultipleStatments = 0x10000,
	SupportsMultipleResults = 0x20000
}

Charset =
{
  latin1_COLLATE_latin1_swedish_ci = 0x8
}

ServerStatus =
{
  InTransaction = 0x1,
  AutoCommit = 0x2,
  MoreResults = 0x4,
  MultiQuery = 0x8,
  BadIndexUsed = 0x10,
  NoIndexUsed = 0x20,
  CursorExists = 0x40,
  LastRowSebd = 0x80,
  DatabaseDropped = 0x100,
  NoBackslashEscapes = 0x200
}

Command =
{
  Query = 3
}


local MAXPACKET = 16777216
local HEADER_SIZE = 4

function decodeHeader(data)
	local response = {}
	response.length = select(2,bin.unpack("C",data,1)) --let's take first byte
	response.seqid = select(2,bin.unpack("C",data,4)) -- and the second one
	return 5,response
end

function errorShower(data,pos)
	local response = {}
	response.errno = bin.unpack("S",data,pos) --getting error number
end

function receiveGreeting(socket)
	local response,error_packet,pos,_ = {},"",0,""
	local catch = function(x) socket:close() stdnse.debug1("initConnection(): "..((x == nil or x =="") and "failed" or x)) end
	local try = nmap.new_try(catch)
	local data = try( socket:receive() )
	pos,response = decodeHeader(data) --decode header

	error_packet = select(2,bin.unpack("H",data,pos))

	if error_packet == "FF" then -- found an error!
		return errorShower(data,pos+1)
	end

	pos,response.prot_ver = bin.unpack("C",data,pos)
	pos,response.serv_ver = bin.unpack("z",data,pos)
	pos,response.thr_num = bin.unpack("I",data,pos)
	pos,response.salt = bin.unpack("z",data,pos)
	pos,response.cap = bin.unpack("S",data,pos)
	pos,response.charset = bin.unpack("C",data,pos)
	pos,response.status = bin.unpack("S",data,pos)
	pos,_ = bin.unpack("A13",data,pos)--skiping a filter
	pos,response.salt_12 = bin.unpack("z",data,pos)

	return true,response
end

--https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
function createLoginHash(password,salt)
	local hash,b1,b2 = "",0,0
  	local _
	
	local hash_s1 = openssl.sha1(password)
	local hash_s2 = openssl.sha1(salt..openssl.sha1(hash_s1))
	for pos=1,#hash_s1 do
		_, b1 = bin.unpack( "C", hash_s1, pos )
		_, b2 = bin.unpack( "C", hash_s2, pos )
		hash = hash..string.char( bit.bxor( b2, b1 ) )
	end
	return hash
end

function loginRequest(socket,params,username,password,salt)
	local response,error_packet,pos = {},"",0
	local packetno = 1
	local catch = function(x) socket:close() stdnse.debug1("initConnection(): "..((x == nil or x =="") and "failed" or x)) end
	local try = nmap.new_try(catch)
	local authversion = {["post41"]={["len"]=20}}		
	if not ssl_status then return false, "No OpenSSL" end
	if #salt ~= authversion[params.authversion]["len"] then return false, "Unsupported authentication version/wrong salt: " .. params.authversion.."/"..salt end

	local clicap = Capabilities.LongPassword
	clicap = clicap + Capabilities.LongColumnFlag
	clicap = clicap + Capabilities.SupportsLoadDataLocal
	clicap = clicap + Capabilities.Speaks41ProtocolNew
	clicap = clicap + Capabilities.InteractiveClient
	clicap = clicap + Capabilities.SupportsTransactions
	clicap = clicap + Capabilities.Support41Auth
	clicap = clicap + Capabilities.SupportsMultipleStatments
	clicap = clicap + Capabilities.SupportsMultipleResults
	local hash = ""
	if password ~= nil and #password > 0 then
		hash = createLoginHash(password,salt)
	end
	local packet = bin.pack( "IICAzp",
		clicap,
		MAXPACKET,
		Charset.latin1_COLLATE_latin1_swedish_ci,
		string.rep("\0", 23),
		username,
		hash
	)

	local tmp = #packet + bit32.lshift( packetno, 24 )

	packet = bin.pack( "I", tmp ) .. packet

	try( socket:send(packet) )
	packet = try( socket:receive() )
end

function decodeFieldPacket(data)
	local response={}
	local pos,field_len=1,0
	local field={"catalog","db","table","org_table","name","org_name"}
	for i=1,6 do
		field_len = select(2,bin.unpack("C",data,pos))		
		response[field[i]]=select(2,bin.unpack("A"..field_len,data,pos+1))
		pos=pos+field_len+1
	end
	pos,response.charsetnr=bin.unpack("S",data,pos+1)
	pos,response.length=bin.unpack("I",data,pos)
	pos,response.data_type=bin.unpack("H",data,pos)
	pos,response.flags=bin.unpack("S",data,pos)
	pos,response.decimals=bin.unpack("C",data,pos)
	
	return response
end

function sqlQuery(socket,query)
	local catch = function(x) socket:close() stdnse.debug1("initConnection(): "..((x == nil or x =="") and "failed" or x)) end
	local try = nmap.new_try(catch)	
	local packet = bin.pack("ICA",#query+1,Command.Query,query)
	try(socket:send(packet))
	local data=try(socket:receive())
	local _
	local pos,response = 5,{}
	--determine the type of packet
	pos,response.type_of_packet=bin.unpack("H",data,pos)
--//////////////Error packet
	if response.type_of_packet == "FF" then
		pos,response.error_num=bin.unpack("S",data,pos)
		pos,response.hash_tag=bin.unpack("A1",data,pos)
		if response.hash_tag == "#" then --4.1+
			pos,response.sqlstate=bin.unpack("A5",data,pos)
			pos,response.message=bin.unpack("z",data,pos)
		else
			pos,response.message=bin.unpack("z",data,pos)
		end
		return false,response
--//////////////Ok packet
	elseif response.type_of_packet == "00" then
		pos,response.affected_rows=bin.unpack("C",data,pos)
		pos,response.insert_id=bin.unpack("C",data,pos)
		pos,response.server_status=bin.unpack("S",data,pos)
		pos,response.warnings_num=bin.unpack("S",data,pos)
		pos,response.message=bin.unpack("z",data,pos)
		return true,response
--//////////////Field packets	
	else
		local packet_len=0
		response.fields={}
		response.field_num=tonumber(response.type_of_packet,16)
		for i=1,response.field_num do
			packet_len=select(2,bin.unpack("S",data,pos))
			table.insert(response.fields,decodeFieldPacket(string.sub(data,pos+4,pos+4+packet_len-1)))
			pos = pos+4+packet_len
		end
--//////////////EOF packet
		pos,response.field_count=bin.unpack("H",data,pos+4)
		pos,response.warning_num=bin.unpack("S",data,pos)
		pos,response.server_status=bin.unpack("S",data,pos)
--//////////////Data packet
		pos,response.data_length=bin.unpack("S",data,pos)
		response.rows={}
		local field_len,k,add,akka,minus=0,1,0,pos,0
-- and select(2,bin.unpack("H",data,pos+6)) ~= "00"
		while select(2,bin.unpack("H",data,pos+6)) ~= "FE" and select(2,bin.unpack("H",data,pos+2)) ~= "FE" do --if we have result	
			if k>1 then pos=pos+4 end--next block of data
			response.rows[k]={}
			for i=1,response.field_num do
				field_len = select(2,bin.unpack("H",data,pos+2))
				if field_len == "FB" then 
					pos=pos+1
					response.rows[k][response.fields[i].name]=""
				else
					if field_len=="FC" then field_len=select(2,bin.unpack("S",data,pos+3)) pos=pos+2 else field_len=tonumber(field_len,16) end--ya,complicated. if the length of data packet takes more than 1 byte, then it looks like FCFFFF, where FFFF is length
					response.rows[k][response.fields[i].name]=select(2,bin.unpack("A"..field_len,data,pos+3))
					pos=pos+field_len+1
				end
			end
			k=k+1
		end	
		return true,response
	end
	
end

