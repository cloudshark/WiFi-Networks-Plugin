--
-- Version info
--
local wpa_plugin_info = {
  version = "1.0.0",
}

set_plugin_info(wpa_plugin_info)

--- wpa.lua
--- figures out the WPA mode for wifi packets
--- based on https://github.com/secdev/scapy/blob/2da3800b87702178a0f60598aebdd7335ce5603d/scapy/layers/dot11.py#L887

local wlan_fc_subtype_f = Field.new("wlan.fc.subtype")
local ssid_f = Field.new("wlan.ssid")
local bssid_f = Field.new("wlan.bssid")
local vendor_f = Field.new("wlan.bssid_resolved")

-- so many ways to get the channel!
local wlan_ds_current_channel_f = Field.new("wlan.ds.current_channel")
local wlan_ht_info_primarychannel_f = Field.new("wlan.ht.info.primarychannel")

local wlan_radio_signal_dbm_f = Field.new("wlan_radio.signal_dbm")
local wlan_radio_noise_dbm_f = Field.new("wlan_radio.noise_dbm")
local wlan_radio_snr_dbm_f = Field.new("wlan_radio.snr")

-- wpa/security determination
local wlan_rsn_akms_type_f = Field.new("wlan.rsn.akms.type")
local wlan_rsn_capabilities_mfpc_f = Field.new("wlan.rsn.capabilities.mfpc")
local wlan_rsn_capabilities_mfpr_f = Field.new("wlan.rsn.capabilities.mfpr")
local wlan_rsn_pcs_type_f = Field.new("wlan.rsn.pcs.type")
local wlan_wfa_ie_wpa_version_f = Field.new("wlan.wfa.ie.wpa.version")
local wlan_wfa_ie_wpa_type_f = Field.new("wlan.wfa.ie.wpa.type")
local wlan_fixed_capabilities_privacy_f = Field.new("wlan.fixed.capabilities.privacy")

networks = {}

local tap = Listener.new("wlan")
function tap.packet(tvb, pinfo, tree)
    local wlan_fc_subtype = wlan_fc_subtype_f()

    -- only look at management beacon and probe-response frames
    if not(wlan_fc_subtype.value == 8 or wlan_fc_subtype.value == 5) then return end

    -- basic information about the network
    local bssid, ssid, vendor = bssid_f(), ssid_f(), vendor_f()

    -- if no ssid field, ssid=nil, we should skip it.
    if not ssid then return end

    local ssid_display = ssid.display

    -- starting in wireshark 4, ssid_f() returns an all-zeros string for blank SSIDs,
    -- detect this and set it back to the empty string which was previously returned
    if ssid_display == "0000000000000000000000000000000000000000000000000000000000000000" then
        ssid_display = ""
    end

    -- starting in wireshark 4, ssid_f() returns non-blank SSID's wrapped in double-quotes ("),
    -- detect this and set it back to the SSID without the surrounding double-quotes
    if #ssid_display >= 2 and string.sub(ssid_display,1,1) == '"' and string.sub(ssid_display,-1,-1) == '"' then
        ssid_display = string.sub(ssid_display,2,-2)
    end

    -- bssid mac address as a string
    local b = tostring(bssid)
    if string.sub(b,1,6) == "ff:ff:" then return end
    if b == "00:00:00:00:00:00" then return end

    if networks[b] == nil then
        networks[b] = {packets=0, signal=0, noise=0, snr=0}
    end

    if #ssid == 0 then
        networks[b].hidden = true
        networks[b].ssid = ""
    else
        networks[b].hidden = false
        networks[b].ssid = ssid_display
    end

    local ds_channel, signal, noise, snr = wlan_ds_current_channel_f(), wlan_radio_signal_dbm_f(), wlan_radio_noise_dbm_f(), wlan_radio_snr_dbm_f()
    local ht_channel = wlan_ht_info_primarychannel_f()

    -- sum each field to do an average at the end
    networks[b].packets = networks[b].packets + 1

    -- WifiExplorer uses a % of signal and noise, and a SNR in dB
    if signal then networks[b].signal = networks[b].signal + signal.value end
    if noise then networks[b].noise = networks[b].noise + noise.value end
    if snr then networks[b].snr = networks[b].snr + snr.value end
    if ds_channel then networks[b].channel = ds_channel.value end
    if ht_channel then networks[b].channel = ht_channel.value end

    -- vendor name resolution TBD
    networks[b].vendor = string.gsub(vendor.display, "_.*", "")

    -- Determine Security Mode
    -- wpa/security determination
    local akms_types = { wlan_rsn_akms_type_f() }
    local mfpc = wlan_rsn_capabilities_mfpc_f()
    local mfpr = wlan_rsn_capabilities_mfpr_f()
    local wfa_wpa_version = wlan_wfa_ie_wpa_version_f()
    local wfa_wpa_types = { wlan_wfa_ie_wpa_type_f() }
    local privacy = wlan_fixed_capabilities_privacy_f()

    -- Determine the verions supported (may be more than one)
    -- and the mode (personal or Enterprise)
    local wpa_version = {}
    local wpa_mode = ""
    local crypto = {}

    -- Microsoft WPA element
    if wfa_wpa_version then
        if #wfa_wpa_types > 0 then
            table.insert(wpa_version, "WPA")

            if hasValue(wfa_wpa_types, 2) then
                wpa_mode = "Personal"
            elseif hasValue(wfa_wpa_types, 1) then
                wpa_mode = "Enterprise"
            else
                wpa_mode = "Unknown"
            end
        else
            table.insert(wpa_version, "WPA multiples")
        end
    end

    -- if this has an RSN with akms types
    if #akms_types > 0 then
        -- if security is supported and requred, is that always WPA3
        if mfpc.value == true and mfpr.value == true then
            if not(hasValue(akms_types, 6) or hasValue(akms_types, 18)) then
                table.insert(wpa_version, "WPA3")
            elseif hasValue(akms_types, 6) then
                -- 802.11w PMF requires type=06
                table.insert(wpa_version, "WPA2")
            elseif hasValue(akms_types, 18) then
                -- OWE mode
                table.insert(wpa_version, "OWE")
            end
        elseif hasMaximum(akms_types, 2) then
            -- if the maximum value for an AKMS suite is 2, then this is WPA2-only.
            table.insert(wpa_version, "WPA2")
        else
            -- otherwise, we have a transition mechanism because the mfpc and mfpr are NOT set if we make it here.
            table.insert(wpa_version, "WPA2/3")
        end

        if hasValue(akms_types, 2) or hasValue(akms_types, 6) or hasValue(akms_types, 8) then
            wpa_mode = "Personal"
        elseif hasValue(akms_types, 1) or hasValue(akms_types, 5) then
            wpa_mode = "Enterprise"
        elseif hasValue(akms_types, 12) then
            wpa_mode = "Enterprise 192-bit"
        elseif hasValue(akms_types, 18) then
            -- this is OWE, we can skip naming it
            wpa_mode = ""
        else
            wpa_mode = "Unknown: " .. akms_types[1].display
        end
    end


    if #wpa_version > 0 then
        if not (wpa_mode == "") then
            table.insert(crypto, table.concat(wpa_version, "/") .. "-" .. wpa_mode)
        else
            table.insert(crypto, table.concat(wpa_version, "/"))
        end
    end

    if #crypto == 0 then
        if privacy.value then
            table.insert(crypto, "WEP")
        else
            table.insert(crypto, "Open")
        end
    end

    if #crypto > 0 then
        networks[b].security = table.concat(crypto, " ")
    end
end

function hasValue(tab, val)
    for _,v in ipairs(tab) do
        if v.value == val then return true end
    end
    return false
end

function hasMaximum(tab, val)
    for _,v in pairs(tab) do
        if v.value > val then return false end
    end
    return true
end

function tap.draw()
    print("BSSID", "SSID", "Security", "Vendor", "Hidden", "Signal", "Noise", "SNR", "Channel")
    for bssid,v in pairs(networks) do
        print(bssid, v.ssid, v.security, v.vendor, v.hidden, v.signal/v.packets, v.noise/v.packets, v.snr/v.packets, v.channel)
    end
end
