from typing import Type

import requests
import json

from maubot import Plugin
from maubot.handlers import event
from mautrix.types import EventType, MessageEvent
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

api_url = "https://www.virustotal.com/vtapi/v2/url/report"


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("api_key")


class VirusTotal(Plugin):

    async def start(self) -> None:
        self.log.debug("startup")
        await super().start()
        self.config.load_and_update()

    @classmethod
    def get_config_class(cls) -> Type[BaseProxyConfig]:
        return Config

    @event.on(EventType.ROOM_MESSAGE)
    async def message_reader(self, evt: MessageEvent) -> None:
        message: str = evt["content"].body

        if message.__contains__("https://") | message.__contains__("http://"):

            for m in message.split(" "):
                if m.startswith("http://") | m.startswith("https://"):

                    api_key = self.config["api_key"]

                    if api_key != "":

                        params = {'apikey': api_key, 'resource': m}
                        response = requests.get(api_url, params=params)

                        response_json = json.loads(response.content)

                        pos: int = response_json['positives']

                        scans = response_json['scans']
                        info: str = ""

                        for scan in scans:
                            if scans[scan]['detected']:
                                info = info + f"- {scan}: *{scans[scan]['result']}* \n"

                        if pos == 0:
                            await evt.respond(
                                f"**No security vendors flagged this URL as malicious** ({m})")

                        elif pos == 1:
                            await evt.respond(f"**This URL maybe malicious**\n([{m}](example.com))\n {info}")

                        else:
                            await evt.respond(f"**MALICIOUS URL!**\n([{m}](example.com))\n {info}")

                            await self.client.redact(
                                room_id=evt.room_id,
                                reason="contained a link that is classified as malicious by virustotal",
                                event_id=evt.event_id,
                            )
