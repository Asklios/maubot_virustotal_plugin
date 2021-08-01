# [VirusTotal](https://www.virustotal.com) [Maubot Plugin](https://github.com/maubot/maubot)
This plugin uses the API of VirusTotal to check URLs and delete messages if necessary.

## Installation
- Download `.mbp` from the latest release and run it on your [Maubot](https://github.com/maubot/maubot) instance.
- Get your own api_key [here](https://developers.virustotal.com/v3.0/reference#getting-started) and insert it into the config.

## Note
Only URLs starting with `https://` or `http://` are recognized.

The public/free VirusTotal API is limited to:
- 4 requests/minute
- 500 requests/day
-  1000000000 requests/month