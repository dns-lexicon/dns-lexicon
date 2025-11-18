"""Compatibility layer for Linode4 (old name for Linode)"""

import logging

from lexicon._private.providers.linode import Provider as LinodeProvider

LOGGER = logging.getLogger(__name__)


# TODO: This provider is kept for retro-compatibility purpose
class Provider(LinodeProvider):
    """Provider for Linode V4"""

    def __init__(self, config):
        LOGGER.error(
            "Linode4 provider is deprecated and will be removed in a future version of Lexicon."
        )
        LOGGER.error("Please use Linode provider instead.")
        super().__init__(config)
