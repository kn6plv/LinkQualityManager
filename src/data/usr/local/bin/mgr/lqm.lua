--[[

	Copyright (C) 2022 Tim Wilkinson
	See Contributors file for additional contributors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	Additional Terms:

	Additional use restrictions exist on the AREDN(TM) trademark and logo.
		See AREDNLicense.txt for more info.

	Attributions to the AREDN Project must be retained in the source code.
	If importing this code into a new or existing project attribution
	to the AREDN project must be added to the source code.

	You must not misrepresent the origin of the material contained within.

	Modified versions must be modified to attribute to the original source
	and be marked in reasonable ways as differentiate it from the original
	version

--]]

local json = require("luci.jsonc")

function enable_mac(mac)
    os.execute("/usr/sbin/iptables -D input_lqm -p udp --destination-port 698 -m mac --mac-source " .. mac .. " -j DROP 2> /dev/null")
end

function disable_mac(mac)
    enable_mac(mac) -- remove any current entry (shouldnt happen but just in case)
    os.execute("/usr/sbin/iptables -I input_lqm -p udp --destination-port 698 -m mac --mac-source " .. mac .. " -j DROP 2> /dev/null")
end

function lqm()

    -- Create filters (cannot create during install as they disappear on reboot)
    os.execute("/usr/sbin/iptables -F input_lqm 2> /dev/null")
    os.execute("/usr/sbin/iptables -X input_lqm 2> /dev/null")
    os.execute("/usr/sbin/iptables -N input_lqm 2> /dev/null")
    os.execute("/usr/sbin/iptables -D INPUT -j input_lqm -m comment --comment 'block low quality links' 2> /dev/null")
    os.execute("/usr/sbin/iptables -I INPUT -j input_lqm -m comment --comment 'block low quality links' 2> /dev/null")
    
    local tracker = {}
    while true
    do
        local f = io.open("/etc/local/lqm.conf")
        local config = json.parse(f:read("*a"))
        f:close()

        local arps = {}
        arptable(
            function (entry)
                arps[entry["IP address"]] = entry
                arps[entry["HW address"]:upper()] = entry
            end
        )
        for mac, station in pairs(iwinfo.nl80211.assoclist(get_ifname("wifi")))
        do
            if station.signal ~= 0 then
                local snr = station.signal - station.noise
                if not tracker[mac] then
                    tracker[mac] = {
                        active = true,
                        dtd = false,
                        snr = 0
                    }
                    enable_mac(mac)
                end

                -- If we have a direct dtd connection to this device, make sure we use that
                local macdtd = false
                local entry = arps[mac]
                if entry then
                    local a, b, c = entry["IP address"]:match("^(%d+%.)(%d+)(%.%d+%.%d+)$")
                    local dtd = arps[string.format("%s%d%s", a, tonumber(b) + 1, c)]
                    if dtd and dtd.Device:match("%.2$") then
                        macdtd = true
                    end
                end
                if macdtd and not tracker[mac].dtd then
                    tracker[mac].dtd = true
                    disable_mac(mac)
                elseif not macdtd and tracker[mac].dtd then
                    tracker[mac].dtd = false
                    enable_mac(mac)
                end
                if not tracker[mac].dtd then
                    if tracker[mac].active then
                        if snr < config.low then
                            tracker[mac].active = false
                            disable_mac(mac)
                        end 
                    elseif not tracker[mac].active then
                        if snr >= config.high then
                            tracker[mac].active = true
                            enable_mac(mac)
                        end 
                    end
                end
                tracker[mac].snr = snr
            end
        end
        wait_for_ticks(60) -- 1 minute
    end
end

return lqm
