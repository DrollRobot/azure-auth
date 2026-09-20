"""Client for Exchange Online cmdlets."""

from __future__ import annotations

from typing import ClassVar

from azure_auth.clients.invoke_command import InvokeCommandClient
from azure_auth.constants import EXCHANGE_RESOURCE


class ExchangeClient(InvokeCommandClient):
    """Run Exchange Online cmdlets without PowerShell.

    User flows default to the Exchange Online PowerShell client id, which is pre-authorised
    for Exchange. App flows need the ``Exchange.ManageAsApp`` application permission and an
    Exchange administrator role assigned to the service principal.

    Example:
        >>> exchange = ExchangeClient(auth)  # doctest: +SKIP
        >>> mailboxes = await exchange.run("Get-Mailbox", ResultSize=10)  # doctest: +SKIP
    """

    RESOURCE: ClassVar[str] = EXCHANGE_RESOURCE
    HOST: ClassVar[str] = "outlook.office365.com"
