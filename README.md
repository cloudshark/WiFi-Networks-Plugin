# WiFi Networks plugin for TShark

The WiFi Networks plugin for TShark identifies WiFi networks and what security
mode a given SSID is advertising via the Beacon or Probe Responses packets found
in the packet capture.

The following security types are detected by the plugin:

* Open
* WEP
* WPA-Personal and WPA-Enterprise
* WPA2-Personal and WPA2-Enterprise
* WPA2/3-Personal and WPA2/3-Enterprise (Transition mode) 
* WPA3-Personal (also known as SAE)
* WPA3-Enterprise
* WPA3-Enterprise 192 bit

We use the term "Enterprise" for the modes utilizing 802.1x authentication and
the term "Personal" for modes that do not.

## Usage

The Lua plugin can be run with `tshark` directly by using the 
`-X lua_script:lua_script_filename` option. Alternatively, the plugin can be
[installed](#Installation) to run every time `tshark` is used.

When `tshark` is run with this plugin enabled, it will print the following
tab-separated table showing any Wireless networks detected via Beacon and Probe
Response packets:

* BSSID: Layer 2 address of the wireless station
* SSID: Network name, if it is not hidden
* Security: Security type employed
* Vendor: OUI of the BSSID resolved to a vendor name
* Hidden: True, if the SSID is hidden
* Signal: Average received signal strength indicator in dBm
* Noise: Average background noise level in dBm
* SNR: Average Signal to Noise ratio in dBm
* Channel: Channel of the Wi-Fi network

## Installation

To install the plugin copy the file `wifi-networks.lua` to your Wireshark
`Personal Lua Plugins` directory.

You can find your Wireshark plugin directory by opening Wireshark and going to
`Help > About Wireshark` and clicking on the `Folders` tab or by running the
command `tshark -G folders`.

## Example

Here is an example of running this plugin on the
[wifi-networks.pcapng](https://www.cloudshark.org/captures/6d72d13108b3)
capture file:

```
# tshark -q -X lua_script:wifi-networks.lua -r wifi-networks.pcapng | column -s $'\t' -t -o " | "
BSSID             | SSID                | Security        | Vendor            | Hidden | Signal | Noise | SNR | Channel
4e:9d:08:53:d1:12 | ACME Corp           | WPA2-Personal   | 4e:9d:08:53:d1:12 | false  | -49    | -74   | 25  | 11
3e:71:ce:4f:32:68 | Ye Olde Coffee Shop | WPA3-Personal   | 3e:71:ce:4f:32:68 | false  | -41    | -74   | 33  | 11
de:dd:d7:51:ba:95 | The Neighbors       | WPA2/3-Personal | de:dd:d7:51:ba:95 | false  | -41    | -73   | 32  | 11
de:4e:cb:fe:62:d4 | ISEEYOURPACKETS     | Open            | de:4e:cb:fe:62:d4 | false  | -39    | -76   | 37  | 11
62:ab:eb:6c:fb:c0 | CloudShark          | WPA2-Personal   | 62:ab:eb:6c:fb:c0 | false  | -34    | -74   | 40  | 11
```

The output of the WiFi Networks plugin is tab separated and can be piped to the
command `column -s $'\t' -t -o " | "` to create a human-readable table.
