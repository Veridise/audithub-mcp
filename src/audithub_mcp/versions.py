"""Authenticated source uploads for new projects and project versions."""

import base64
from io import BytesIO
from zipfile import is_zipfile

from audithub_sdk.api.versions_api import VersionsApi
from audithub_sdk.models.temp_version import TempVersion
from audithub_sdk.rest import RESTResponse
from audithub_sdk_ext import AuthenticatedApiClient
from pydantic import TypeAdapter

from audithub_mcp.models import InlineZipArchive, ProjectGitSource, ProjectSource, TempVersionId

_temp_id = TypeAdapter(TempVersionId)


async def upload_version_archive(
    client: AuthenticatedApiClient,
    *,
    organization_id: int,
    project_id: int | None = None,
    archive: str | tuple[str, bytes],
    name: str | None,
    commit_hash: str | None,
    is_deployed: bool | None,
) -> RESTResponse:
    """Send ZIP bytes as a multipart file. An absent project ID stages a temporary version."""
    path_params = {"organization_id": organization_id}
    if project_id is None:
        path = "/organizations/{organization_id}/temp-versions"
    else:
        path = "/organizations/{organization_id}/projects/{project_id}/versions"
        path_params["project_id"] = project_id

    # The generated upload methods in SDK 1.0.2 send the path as a text form field.
    form = {"name": name, "commit_hash": commit_hash, "is_deployed": is_deployed}
    request = client.param_serialize(
        method="POST",
        resource_path=path,
        path_params=path_params,
        header_params={"Accept": "application/json", "Content-Type": "multipart/form-data"},
        post_params=[(key, value) for key, value in form.items() if value is not None],
        files={"archive": archive},
        auth_settings=["OpenIdConnect"],
    )
    response: RESTResponse = await client.call_api(*request)
    await response.read()  # type: ignore[no-untyped-call]  # Generated SDK method.
    return response


async def stage_project_sources(
    client: AuthenticatedApiClient,
    *,
    organization_id: int,
    source: ProjectSource,
    archive: str | InlineZipArchive | None,
    version_name: str | None,
    commit_hash: str | None,
    is_deployed: bool | None,
) -> str:
    """Stage a ZIP upload or URL in the organization and return its temporary version ID."""
    if archive is not None:
        upload: str | tuple[str, bytes]
        if isinstance(archive, InlineZipArchive):
            try:
                contents = base64.b64decode(archive.content_base64, validate=True)
            except ValueError:
                raise RuntimeError("content_base64 must contain a base64-encoded ZIP.") from None
            if not is_zipfile(BytesIO(contents)):
                raise RuntimeError("The uploaded archive must be a ZIP file.")
            upload = (archive.filename, contents)
        else:
            if not is_zipfile(archive):
                raise RuntimeError("The archive path must identify a readable ZIP on the server.")
            upload = archive
        response = await upload_version_archive(
            client,
            organization_id=organization_id,
            archive=upload,
            name=version_name,
            commit_hash=commit_hash,
            is_deployed=is_deployed,
        )
        staged = TempVersion.model_validate(
            client.response_deserialize(response, {"200": "TempVersion"}).data
        )
    else:
        assert source.url is not None
        staged = await VersionsApi(
            client
        ).post_temp_version_with_url_organizations_organization_id_temp_versions_url_post(  # noqa: E501
            organization_id=organization_id,
            input_type=source.input_type,
            url=source.url,
            revision=source.revision if isinstance(source, ProjectGitSource) else None,
            includes_submodules=source.includes_submodules
            if isinstance(source, ProjectGitSource)
            else None,
            name=version_name,
            commit_hash=commit_hash,
            is_deployed=is_deployed,
        )
    return _temp_id.validate_python(staged.id)
