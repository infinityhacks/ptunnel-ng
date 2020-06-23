ptunnel_protocol = Proto("PTunnel-NG", "PTunnel-NG Protocol")

icmp_type        = ProtoField.uint8("icmp.type",               "type",          base.HEX)
icmp_code        = ProtoField.uint8("icmp.code",               "code",          base.HEX)
icmp_chksm       = ProtoField.uint16("icmp.chksm",             "chksm",         base.HEX)

magic            = ProtoField.uint32("ptunnel.magic",          "magic",         base.HEX)

ptunnel_protocol.fields = { icmp_type, icmp_code, icmp_chksm, magic }

function ptunnel_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = ptunnel_protocol.name

  local subtree = tree:add(ptunnel_protocol, buffer(), "PTunnel Protocol Data")
  local icmpHeaderSubtree = subtree:add(ptunnel_protocol, buffer(), "ICMP Header")

  icmpHeaderSubtree:add_le(icmp_type,      buffer(0,1))
  icmpHeaderSubtree:add_le(icmp_code,      buffer(1,1))
  icmpHeaderSubtree:add_le(icmp_chksm,     buffer(2,2))

  icmpHeaderSubtree:add_le(magic,          buffer(4,4))
end

local icmp = DissectorTable.get("ip.proto")
icmp:add(1, ptunnel_protocol)

local function heuristic_checker(buffer, pinfo, tree)
    length = buffer:len()
    --if length < 28 + 8 then return false end

    local magic = buffer(8,4):uint32()
    if magic == 0xdeadc0de
    then
        ptunnel_protocol.dissector(buffer, pinfo, tree)
        return true
    else
        return false
    end
end

ptunnel_protocol:register_heuristic("ip", heuristic_checker)

--for k,v in pairs(DissectorTable.list()) do
--  print(k,v)
--end
