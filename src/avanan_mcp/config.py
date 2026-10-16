# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Process settings. Holds no credentials: those arrive per request as headers."""

from pydantic_settings import BaseSettings, SettingsConfigDict

# Infinity Portal gateway per data region; the API lives under /app/hec-api.
REGION_GATEWAYS: dict[str, str] = {
    "eu": "https://cloudinfra-gw.portal.checkpoint.com",
    "us": "https://cloudinfra-gw-us.portal.checkpoint.com",
    "ca": "https://cloudinfra-gw.ca.portal.checkpoint.com",
    "au": "https://cloudinfra-gw.ap.portal.checkpoint.com",
    "uk": "https://cloudinfra-gw.uk.portal.checkpoint.com",
    "uae": "https://cloudinfra-gw.me.portal.checkpoint.com",
    "in": "https://cloudinfra-gw.in.portal.checkpoint.com",
}
# Where the API key is exchanged for a token when no region is given.
AUTH_GATEWAY = REGION_GATEWAYS["eu"]

REGION_ALIASES: dict[str, str] = {
    **{code: code for code in REGION_GATEWAYS},
    "ap": "au",
    "me": "uae",
    "gb": "uk",
    "usa": "us",
    "europe": "eu",
}


def resolve_region(value: str | None) -> str | None:
    text = (value or "").strip().lower()
    return REGION_ALIASES.get(text) if text else None


class Settings(BaseSettings):
    # extra="ignore": the runtime injects variables this project does not declare.
    model_config = SettingsConfigDict(extra="ignore")

    mcp_http_port: int = 8080
    mcp_http_host: str = "0.0.0.0"
    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()
