"""Marketplace catalog Pydantic schema

Each catalog/*.yaml file maps to one CatalogEntry describing an MCP service template that
can be installed from the MCP Center UI. The "Install" form the vendor sees is generated
dynamically from this schema.

Design principles:
  - extra='forbid' -- unknown fields raise immediately, so a vendor's typo in a field name never fails silently
  - the secret + required flags tell the UI how to render the field (password / plain input)
  - docker.tag should be pinned by us to a verified version; shipping with latest is not recommended
"""
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Single source of truth for the docker argv policy. The same rules are applied again by the
# orchestrator after it reads image_args / image_command from the DB -- see the argv_policy module
# docstring for why both boundaries validate (stored-injection threat model + SAST visibility).
from src.marketplace.argv_policy import (
    validate_command_tokens,
    validate_docker_args,
    validate_image_name,
    validate_tag,
)


class EnvVarDef(BaseModel):
    """Definition of one environment variable - the vendor fills in one field at install time"""
    model_config = ConfigDict(extra='forbid')

    name: str = Field(..., description="Env var key, e.g. PERPLEXITY_API_KEY")
    label: str = Field(..., description="Label shown in the UI")
    help: Optional[str] = Field(None, description="Help text; may contain a URL")
    required: bool = True
    secret: bool = Field(
        False,
        description="True -> the UI uses a password input and the backend stores it encrypted",
    )
    default: Optional[str] = Field(
        None,
        description="Default value; not recommended when secret=True",
    )
    pattern: Optional[str] = Field(
        None,
        description="Regex validation; enforced by both the UI and the backend",
    )
    error_message: Optional[str] = Field(
        None,
        description="Message shown when regex validation fails",
    )


class DockerSpec(BaseModel):
    """Container launch settings"""
    model_config = ConfigDict(extra='forbid')

    image: str = Field(..., description="e.g. mcp/perplexity-ask")
    tag: str = Field("latest", description="Pinning a specific version is recommended")
    args: List[str] = Field(
        default_factory=lambda: ["--rm"],
        description="docker run args",
    )
    transport: str = Field(
        "http",
        description="stdio = needs the supergateway bridge; http = the image ships its own HTTP server",
    )
    container_port: int = Field(
        8080,
        description="Port the container listens on internally in HTTP mode (used for the -p mapping)",
    )
    command: List[str] = Field(
        default_factory=list,
        description="entrypoint args appended after image_ref (e.g. ['--config','/app/cfg.yaml'])",
    )

    # All validators below delegate to src/marketplace/argv_policy -- there is only one policy,
    # and the orchestrator applies the very same rules at the execution boundary.

    @field_validator("image")
    @classmethod
    def _validate_image(cls, v: str) -> str:
        return validate_image_name(v)

    @field_validator("tag")
    @classmethod
    def _validate_tag(cls, v: str) -> str:
        """The tag is joined into `image:tag` and stored in the DB, so it must be validated too (it never was)."""
        return validate_tag(v)

    @field_validator("args")
    @classmethod
    def _validate_args(cls, v: List[str]) -> List[str]:
        """Flag-level allowlist (default-deny). A character allowlist cannot stop -v /:/host."""
        return validate_docker_args(v)

    @field_validator("command")
    @classmethod
    def _validate_command(cls, v: List[str]) -> List[str]:
        """entrypoint args: not docker flags, so a character allowlist is sufficient."""
        return validate_command_tokens(v)


class CatalogEntry(BaseModel):
    """A single Marketplace item"""
    model_config = ConfigDict(extra='forbid')

    id: str = Field(..., description="Unique ID; also the catalog file name (without .yaml)")
    name: str = Field(..., description="Display name in the UI")
    description: str
    category: str = "general"
    icon: Optional[str] = Field(
        None,
        description="File name under static/marketplace-icons/ (optional)",
    )

    docker: DockerSpec
    env_vars: List[EnvVarDef] = Field(default_factory=list)

    docs_url: Optional[str] = None

    # Offline install: image tar file name (located under images/ in the catalog directory).
    # When unset, the convention `<id>.tar` is used. "Install" = the backend loads this tar via the
    # docker SDK; "Deploy" = start the container (the image must already be installed).
    image_tar: Optional[str] = Field(
        None,
        description=(
            "Tar file name under images/; defaults to the <id>.tar convention. "
            "The placeholders {tag} / {image} / {id} are supported, e.g. mit2i_{tag}.tar.gz -- "
            "when upgrading, only docker.tag needs to change and the file name follows automatically."
        ),
    )

    def image_tar_name(self) -> str:
        """Resolve the image tar file name.

        An explicit value takes precedence; otherwise the <id>.tar convention applies. The {tag} /
        {image} / {id} placeholders are supported so the file name can be derived from docker.tag --
        one source of truth, so an upgrade does not require editing two places.
        image may contain a registry path (a/b/c); '/' is replaced with '_' when it goes into the file name.
        """
        template = self.image_tar or f"{self.id}.tar"
        try:
            return template.format(
                id=self.id,
                image=self.docker.image.replace("/", "_"),
                tag=self.docker.tag,
            )
        except (KeyError, IndexError) as e:
            raise ValueError(
                f"image_tar contains unknown placeholder {e} "
                f"(only {{tag}} {{image}} {{id}} are supported): {template!r}"
            ) from e

    @model_validator(mode="after")
    def _validate_image_tar_template(self):
        """A misspelled placeholder must fail at YAML load time (the loader skips the broken entry)
        instead of blowing up with a 500 in image_tar_name() only when the marketplace listing is requested."""
        self.image_tar_name()
        return self

    def public_dict(self) -> dict:
        """Used by the API to return the entry to the frontend; currently identical to model_dump().
        Adjust here if internal fields ever need to be hidden"""
        return self.model_dump()
