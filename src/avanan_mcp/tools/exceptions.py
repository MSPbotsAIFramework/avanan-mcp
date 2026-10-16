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
"""Allow (whitelist) and block (blacklist) exception rules."""

from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import HecClient
from ._common import DESTRUCTIVE, READ_ONLY, WRITES, ClientFactory, list_result, request_data, run_tool, single_result

ExcType = Annotated[
    Literal["whitelist", "blacklist"], Field(description="Exception list: whitelist (allow) or blacklist (block).")
]
ExcId = Annotated[str, Field(description="Exception id from hec_list_exceptions.")]
SenderEmail = Annotated[str | None, Field(description="Sender e-mail address.")]
SenderDomain = Annotated[str | None, Field(description="Sender domain.")]
SenderName = Annotated[str | None, Field(description="Sender display name.")]
Recipient = Annotated[str | None, Field(description="Recipient e-mail address.")]
Subject = Annotated[str | None, Field(description="E-mail subject.")]
AttachmentMd5 = Annotated[str | None, Field(description="Attachment MD5 hash.")]
Comment = Annotated[str | None, Field(description="Why the rule exists.")]
EmailMatching = Annotated[Literal["matching", "contains"] | None, Field(description="How senderEmail is matched.")]
DomainMatching = Annotated[Literal["contains", "endswith"] | None, Field(description="How senderDomain is matched.")]
SubjectMatching = Annotated[Literal["matching", "contains"] | None, Field(description="How subject is matched.")]


def _rule(**values: Any) -> dict:
    body = request_data(values)
    if not body["requestData"]:
        raise ValueError("Give at least one exception field (for example senderEmail or senderDomain)")
    return body


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def hec_list_exceptions(excType: ExcType) -> str:
        """List the allow (whitelist) or block (blacklist) exception rules."""

        async def action(client: HecClient) -> dict:
            return list_result(await client.request("GET", f"/v1.0/exceptions/{excType}"))

        return await run_tool("hec_list_exceptions", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def hec_add_exception(
        excType: ExcType,
        senderEmail: SenderEmail = None,
        senderDomain: SenderDomain = None,
        senderName: SenderName = None,
        recipient: Recipient = None,
        subject: Subject = None,
        attachmentMd5: AttachmentMd5 = None,
        comment: Comment = None,
        senderEmailMatching: EmailMatching = None,
        senderDomainMatching: DomainMatching = None,
        subjectMatching: SubjectMatching = None,
    ) -> str:
        """Add an allow or block rule. Changes how mail is filtered: only when the user explicitly asks."""

        async def action(client: HecClient) -> Any:
            body = _rule(
                senderEmail=senderEmail,
                senderDomain=senderDomain,
                senderName=senderName,
                recipient=recipient,
                subject=subject,
                attachmentMd5=attachmentMd5,
                comment=comment,
                senderEmailMatching=senderEmailMatching or ("matching" if senderEmail else None),
                senderDomainMatching=senderDomainMatching or ("endswith" if senderDomain else None),
                subjectMatching=subjectMatching or ("contains" if subject else None),
            )
            result = single_result(await client.request("POST", f"/v1.0/exceptions/{excType}", body=body))
            return result if result else {"added": True, "excType": excType}

        return await run_tool("hec_add_exception", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def hec_update_exception(
        excType: ExcType,
        excId: ExcId,
        senderEmail: SenderEmail = None,
        senderDomain: SenderDomain = None,
        senderName: SenderName = None,
        recipient: Recipient = None,
        subject: Subject = None,
        attachmentMd5: AttachmentMd5 = None,
        comment: Comment = None,
        senderEmailMatching: EmailMatching = None,
        senderDomainMatching: DomainMatching = None,
        subjectMatching: SubjectMatching = None,
    ) -> str:
        """Update an allow or block rule. Changes how mail is filtered: only when the user explicitly asks."""

        async def action(client: HecClient) -> Any:
            body = _rule(
                senderEmail=senderEmail,
                senderDomain=senderDomain,
                senderName=senderName,
                recipient=recipient,
                subject=subject,
                attachmentMd5=attachmentMd5,
                comment=comment,
                senderEmailMatching=senderEmailMatching,
                senderDomainMatching=senderDomainMatching,
                subjectMatching=subjectMatching,
            )
            path = f"/v1.0/exceptions/{excType}/{quote(excId.strip(), safe='')}"
            result = single_result(await client.request("PUT", path, body=body))
            return result if result else {"updated": True, "excType": excType, "excId": excId}

        return await run_tool("hec_update_exception", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def hec_delete_exception(excType: ExcType, excId: ExcId) -> str:
        """Delete an allow or block rule. Irreversible: only when the user explicitly asks for that rule id."""

        async def action(client: HecClient) -> Any:
            path = f"/v1.0/exceptions/{excType}/delete/{quote(excId.strip(), safe='')}"
            result = single_result(await client.request("POST", path))
            return result if result else {"deleted": True, "excType": excType, "excId": excId}

        return await run_tool("hec_delete_exception", client_factory, action)
