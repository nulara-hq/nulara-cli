"""The products the tests hand the core, one per surface."""

from dataclasses import replace

import nulara

NULARA = nulara.PRODUCT
# What a development entrypoint hands the core: the same product, local API.
NULARA_DEV = replace(NULARA, api_url="http://localhost:5710/v1/app")
