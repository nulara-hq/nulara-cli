from importlib.metadata import version
from importlib.resources import files

from nulara.core.config import Product, Surface
from nulara.core.main import build_app, run

PRODUCT = Product(
    name="nulara",
    display_name="Nulara",
    api_url="https://api.nulara.de/v1/app",
    oauth_client_id="nulara-cli",
    manifest=files(__name__).joinpath("spec.json"),
    version=version("nulara"),
    skill=files(__name__).joinpath("skill/SKILL.md"),
)


def main() -> None:
    run(lambda: build_app(PRODUCT, Surface.CUSTOMER))


__all__ = ["PRODUCT", "main"]
