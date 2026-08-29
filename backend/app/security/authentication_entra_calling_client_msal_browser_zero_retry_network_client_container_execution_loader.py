"""Controlled one-shot Docker execution loader for the exact Step 230 proof."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
from builtins import BaseExceptionGroup
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_isolation_readiness import (
    CONTAINER_ARCHITECTURE,
    CONTAINER_CPUS_MILLI,
    CONTAINER_EXECUTION_TIMEOUT_SECONDS,
    CONTAINER_MEMORY_BYTES,
    CONTAINER_MEMORY_SWAP_BYTES,
    CONTAINER_MOUNT_TARGET,
    CONTAINER_NETWORK_MODE,
    CONTAINER_NODE_PATH,
    CONTAINER_OPERATING_SYSTEM,
    CONTAINER_PIDS_LIMIT,
    CONTAINER_SHM_BYTES,
    CONTAINER_STOP_TIMEOUT_SECONDS,
    CONTAINER_USER,
    CONTAINER_WORKDIR,
    MAXIMUM_STDERR_BYTES,
    MAXIMUM_STDOUT_BYTES,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    HARNESS_FILE_NAME,
    HARNESS_SHA256,
    NODE_VERSION,
    RUNNER_FILE_NAME,
    RUNNER_SHA256,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    ADAPTER_SHA256,
)

MAX_DOCKER_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_NODE_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_INSPECT_BYTES = 256 * 1024
MAX_COMMAND_STDERR_BYTES = 4 * 1024
DOCKER_COMMAND_TIMEOUT_SECONDS = 20
MAX_IMAGE_LAYERS = 128
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
COMMAND_SEQUENCE = (
    "docker_version",
    "image_inspect",
    "container_create",
    "container_inspect_before_start",
    "node_binary_copy",
    "container_start_attach",
    "container_inspect_after_exit",
    "container_remove_finally",
)


class EntraCallingClientMSALZeroRetryContainerExecutionLoaderError(ValueError):
    """Sanitized Step 230 loader failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public inputs."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_image_id(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("sha256:")
        and _is_sha256(value.removeprefix("sha256:"))
    )


def _is_public_version_token(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and all(
            character.isascii() and (character.isalnum() or character in ".+-_")
            for character in value
        )
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Docker JSON key")
        result[key] = value
    return result


def _json_document(value: bytes, maximum: int, description: str) -> dict[str, Any]:
    if type(value) is not bytes or not 2 <= len(value) <= maximum:
        raise ValueError(f"{description} size is invalid")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{description} encoding is invalid") from None
    try:
        document = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError(f"{description} JSON is invalid") from None
    if type(document) is not dict:
        raise ValueError(f"{description} must be an object")
    return document


def _hash_regular_file(path: Path, maximum: int, expected: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError("approved executable must be a regular non-symlink file")
    size = path.stat().st_size
    if type(size) is not int or not 1 <= size <= maximum:
        raise ValueError("approved executable size is invalid")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise ValueError("approved executable exceeded its size bound")
            digest.update(chunk)
    if total != size or digest.hexdigest() != expected:
        raise ValueError("approved executable digest changed")


def _validate_docker_path(path_value: object, approved_sha256: str) -> str:
    if (
        type(path_value) is not str
        or not path_value
        or not os.path.isabs(path_value)
        or os.path.realpath(path_value) != path_value
    ):
        raise _ArgumentTypeError(
            "canonical absolute Docker executable path is required"
        )
    path = Path(path_value)
    if not os.access(path, os.X_OK):
        raise ValueError("Docker executable is not executable")
    _hash_regular_file(path, MAX_DOCKER_EXECUTABLE_BYTES, approved_sha256)
    return path_value


def _container_arguments() -> tuple[str, ...]:
    return (
        "--permission",
        "--allow-fs-read=/work",
        f"/work/{RUNNER_FILE_NAME}",
        f"/work/{HARNESS_FILE_NAME}",
        "/work/authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs",
        HARNESS_SHA256,
        ADAPTER_SHA256,
    )


def _environment_overrides() -> dict[str, str]:
    return {
        "ALL_PROXY": "",
        "HOME": "/nonexistent",
        "HTTPS_PROXY": "",
        "HTTP_PROXY": "",
        "NODE_OPTIONS": "",
        "NODE_USE_ENV_PROXY": "0",
        "NO_COLOR": "1",
        "NO_PROXY": "",
        "TEMP": "/nonexistent",
        "TMP": "/nonexistent",
        "USERPROFILE": "/nonexistent",
        "all_proxy": "",
        "http_proxy": "",
        "https_proxy": "",
        "no_proxy": "",
    }


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryContainerExecutionRequest:
    image_id: str
    approved_docker_executable_sha256: str
    approved_node_executable_sha256: str
    adapter: bytes
    harness: bytes
    runner: bytes

    def __post_init__(self) -> None:
        if (
            not _is_image_id(self.image_id)
            or not _is_sha256(self.approved_docker_executable_sha256)
            or not _is_sha256(self.approved_node_executable_sha256)
            or type(self.adapter) is not bytes
            or type(self.harness) is not bytes
            or type(self.runner) is not bytes
            or len({id(self.adapter), id(self.harness), id(self.runner)}) != 3
            or hashlib.sha256(self.adapter).hexdigest() != ADAPTER_SHA256
            or hashlib.sha256(self.harness).hexdigest() != HARNESS_SHA256
            or hashlib.sha256(self.runner).hexdigest() != RUNNER_SHA256
        ):
            raise ValueError("container execution request is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryContainerExecutionEvidence:
    docker_cli_sha256: str
    image_id: str
    docker_version_document: bytes
    image_inspect_document: bytes
    container_inspect_before_start_document: bytes
    container_inspect_after_exit_document: bytes
    node_executable_sha256: str
    stdout: bytes
    stderr: bytes
    exit_code: int
    command_sequence: tuple[str, ...]
    cleanup_succeeded: bool
    _sealed_attestation: object = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            not _is_sha256(self.docker_cli_sha256)
            or not _is_image_id(self.image_id)
            or type(self.docker_version_document) is not bytes
            or not 2 <= len(self.docker_version_document) <= MAX_INSPECT_BYTES
            or type(self.image_inspect_document) is not bytes
            or not 2 <= len(self.image_inspect_document) <= MAX_INSPECT_BYTES
            or type(self.container_inspect_before_start_document) is not bytes
            or not 2
            <= len(self.container_inspect_before_start_document)
            <= MAX_INSPECT_BYTES
            or type(self.container_inspect_after_exit_document) is not bytes
            or not 2
            <= len(self.container_inspect_after_exit_document)
            <= MAX_INSPECT_BYTES
            or not _is_sha256(self.node_executable_sha256)
            or type(self.stdout) is not bytes
            or not 1 <= len(self.stdout) <= MAXIMUM_STDOUT_BYTES
            or type(self.stderr) is not bytes
            or self.stderr
            or len(self.stderr) > MAXIMUM_STDERR_BYTES
            or type(self.exit_code) is not int
            or self.exit_code != 0
            or type(self.command_sequence) is not tuple
            or self.command_sequence != COMMAND_SEQUENCE
            or not all(type(value) is str for value in self.command_sequence)
            or type(self.cleanup_succeeded) is not bool
            or not self.cleanup_succeeded
        ):
            raise ValueError("container execution evidence is invalid")


def _build_attestation_helpers() -> tuple[
    Callable[
        [EntraCallingClientMSALZeroRetryContainerExecutionEvidence],
        EntraCallingClientMSALZeroRetryContainerExecutionEvidence,
    ],
    Callable[[EntraCallingClientMSALZeroRetryContainerExecutionEvidence], bool],
]:
    token = object()

    def attest(
        evidence: EntraCallingClientMSALZeroRetryContainerExecutionEvidence,
    ) -> EntraCallingClientMSALZeroRetryContainerExecutionEvidence:
        object.__setattr__(evidence, "_sealed_attestation", token)
        return evidence

    def is_attested(
        evidence: EntraCallingClientMSALZeroRetryContainerExecutionEvidence,
    ) -> bool:
        return evidence._sealed_attestation is token

    return attest, is_attested


_attest_sealed, is_sealed_container_execution_evidence = _build_attestation_helpers()


class EntraCallingClientMSALZeroRetryContainerExecutionTransport(Protocol):
    def __call__(
        self,
        request: EntraCallingClientMSALZeroRetryContainerExecutionRequest,
    ) -> EntraCallingClientMSALZeroRetryContainerExecutionEvidence: ...


def _image_projection(document: bytes, expected_image_id: str) -> dict[str, object]:
    value = _json_document(document, MAX_INSPECT_BYTES, "image inspection")
    if (
        type(value.get("Id")) is not str
        or value["Id"] != expected_image_id
        or value.get("Os") != CONTAINER_OPERATING_SYSTEM
        or value.get("Architecture") != CONTAINER_ARCHITECTURE
        or type(value.get("Size")) is not int
        or not 1 <= value["Size"] <= MAX_IMAGE_BYTES
    ):
        raise ValueError("image identity or platform is invalid")
    config = value.get("Config")
    rootfs = value.get("RootFS")
    if type(config) is not dict or type(rootfs) is not dict:
        raise ValueError("image configuration or rootfs is invalid")
    if (
        config.get("Volumes") not in (None, {})
        or config.get("ExposedPorts") not in (None, {})
        or config.get("Healthcheck") not in (None, {})
        or config.get("OnBuild") not in (None, [])
    ):
        raise ValueError("image declares an unapproved runtime surface")
    environment = config.get("Env")
    if type(environment) is not list or not environment:
        raise ValueError("image environment is invalid")
    image_environment: dict[str, str] = {}
    for item in environment:
        if type(item) is not str or "=" not in item:
            raise ValueError("image environment entry is invalid")
        name, value_text = item.split("=", 1)
        if (
            name in image_environment
            or name not in {"PATH", "NODE_VERSION", "YARN_VERSION"}
            or not value_text
            or len(value_text) > 2048
        ):
            raise ValueError("image environment is outside the approved profile")
        image_environment[name] = value_text
    if image_environment.get("NODE_VERSION") != NODE_VERSION.removeprefix("v"):
        raise ValueError("image Node version declaration changed")
    if "PATH" not in image_environment or not image_environment["PATH"].startswith("/"):
        raise ValueError("image PATH is invalid")
    layers = rootfs.get("Layers")
    if (
        rootfs.get("Type") != "layers"
        or type(layers) is not list
        or not 1 <= len(layers) <= MAX_IMAGE_LAYERS
        or any(not _is_image_id(layer) for layer in layers)
        or len(layers) != len(set(layers))
    ):
        raise ValueError("image rootfs layer identities are invalid")
    return {
        "id": expected_image_id,
        "os": value["Os"],
        "architecture": value["Architecture"],
        "size": value["Size"],
        "layers": tuple(layers),
        "environment": image_environment,
        "declaredVolumes": False,
        "declaredExposedPorts": False,
        "declaredHealthcheck": False,
        "declaredOnBuild": False,
    }


def _docker_version_projection(document: bytes) -> dict[str, object]:
    value = _json_document(document, MAX_INSPECT_BYTES, "Docker version")
    if (
        value.get("Os") != CONTAINER_OPERATING_SYSTEM
        or value.get("Arch") != CONTAINER_ARCHITECTURE
        or not _is_public_version_token(value.get("Version"), 64)
        or not _is_public_version_token(value.get("ApiVersion"), 32)
    ):
        raise ValueError("Docker server identity is invalid")
    return {
        "os": value["Os"],
        "architecture": value["Arch"],
        "version": value["Version"],
        "apiVersion": value["ApiVersion"],
    }


def _environment_map(values: object) -> dict[str, str]:
    if type(values) is not list:
        raise ValueError("container environment is invalid")
    result: dict[str, str] = {}
    for item in values:
        if type(item) is not str or "=" not in item:
            raise ValueError("container environment entry is invalid")
        name, value = item.split("=", 1)
        if not name or name in result:
            raise ValueError("container environment names are invalid")
        result[name] = value
    return result


def _container_projection(
    document: bytes,
    *,
    image_id: str,
    expect_running: bool,
    expected_image_environment: dict[str, str],
    expected_container_id: str | None = None,
) -> dict[str, object]:
    value = _json_document(document, MAX_INSPECT_BYTES, "container inspection")
    config = value.get("Config")
    host = value.get("HostConfig")
    state = value.get("State")
    mounts = value.get("Mounts")
    network_settings = value.get("NetworkSettings")
    if not all(type(item) is dict for item in (config, host, state, network_settings)):
        raise ValueError("container inspection sections are invalid")
    if (
        type(value.get("Id")) is not str
        or len(value["Id"]) != 64
        or any(character not in "0123456789abcdef" for character in value["Id"])
        or (expected_container_id is not None and value["Id"] != expected_container_id)
        or value.get("Image") != image_id
        or value.get("Path") != CONTAINER_NODE_PATH
        or value.get("Args") != list(_container_arguments())
        or config.get("Image") != image_id
        or config.get("User") != CONTAINER_USER
        or config.get("WorkingDir") != CONTAINER_WORKDIR
        or config.get("Entrypoint") != [CONTAINER_NODE_PATH]
        or config.get("Cmd") != list(_container_arguments())
    ):
        raise ValueError("container identity or command is invalid")
    actual_environment = _environment_map(config.get("Env"))
    expected_environment = {
        **expected_image_environment,
        **_environment_overrides(),
    }
    if actual_environment != expected_environment:
        raise ValueError("container environment projection changed")
    if (
        host.get("NetworkMode") != CONTAINER_NETWORK_MODE
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or host.get("CapAdd") not in (None, [])
        or host.get("CapDrop") != ["ALL"]
        or host.get("PidsLimit") != CONTAINER_PIDS_LIMIT
        or host.get("Memory") != CONTAINER_MEMORY_BYTES
        or host.get("MemorySwap") != CONTAINER_MEMORY_SWAP_BYTES
        or host.get("NanoCpus") != CONTAINER_CPUS_MILLI * 1_000_000
        or host.get("ShmSize") != CONTAINER_SHM_BYTES
        or host.get("AutoRemove") is not False
        or host.get("PublishAllPorts") is not False
        or host.get("PortBindings") not in (None, {})
        or host.get("Devices") not in (None, [])
        or host.get("DeviceRequests") not in (None, [])
        or host.get("Binds") not in (None, [])
        or host.get("Tmpfs") not in (None, {})
        or host.get("VolumesFrom") not in (None, [])
        or host.get("Links") not in (None, [])
        or host.get("ExtraHosts") not in (None, [])
        or host.get("Dns") not in (None, [])
        or host.get("DnsOptions") not in (None, [])
        or host.get("DnsSearch") not in (None, [])
        or host.get("Sysctls") not in (None, {})
        or host.get("PidMode") not in ("", "private")
        or host.get("IpcMode") != "private"
        or host.get("UTSMode") not in ("", "private")
        or host.get("CgroupnsMode") != "private"
        or host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}
        or host.get("LogConfig") != {"Type": "none", "Config": {}}
    ):
        raise ValueError("applied container isolation profile changed")
    if config.get("Healthcheck") != {"Test": ["NONE"]}:
        raise ValueError("container healthcheck disablement changed")
    networks = network_settings.get("Networks")
    if (
        type(networks) is not dict
        or set(networks) != {"none"}
        or type(networks["none"]) is not dict
        or networks["none"].get("Gateway") not in (None, "")
        or networks["none"].get("IPAddress") not in (None, "")
        or networks["none"].get("GlobalIPv6Address") not in (None, "")
        or network_settings.get("Ports") not in (None, {})
    ):
        raise ValueError("container network attachment state changed")
    security = host.get("SecurityOpt")
    if type(security) is not list or set(security) != {
        "no-new-privileges=true",
        "seccomp=builtin",
    }:
        raise ValueError("applied container security options changed")
    if (
        type(mounts) is not list
        or len(mounts) != 1
        or type(mounts[0]) is not dict
        or mounts[0].get("Type") != "bind"
        or mounts[0].get("Destination") != CONTAINER_MOUNT_TARGET
        or mounts[0].get("RW") is not False
        or type(mounts[0].get("Source")) is not str
        or not mounts[0]["Source"]
        or "docker.sock" in mounts[0]["Source"].lower()
    ):
        raise ValueError("applied container mount profile changed")
    if expect_running:
        if (
            state.get("Running") is not False
            or state.get("Status") != "exited"
            or state.get("ExitCode") != 0
            or type(state.get("StartedAt")) is not str
            or not state["StartedAt"]
            or type(state.get("FinishedAt")) is not str
            or not state["FinishedAt"]
        ):
            raise ValueError("container post-execution state is invalid")
    elif (
        state.get("Running") is not False
        or state.get("Status") != "created"
        or state.get("ExitCode") != 0
    ):
        raise ValueError("container pre-start state is invalid")
    return {
        "image": image_id,
        "path": CONTAINER_NODE_PATH,
        "args": _container_arguments(),
        "networkMode": host["NetworkMode"],
        "readOnlyRoot": host["ReadonlyRootfs"],
        "capDrop": tuple(host["CapDrop"]),
        "securityOptions": tuple(sorted(security)),
        "user": config["User"],
        "workdir": config["WorkingDir"],
        "mountCount": len(mounts),
        "mountDestination": mounts[0]["Destination"],
        "mountReadOnly": not mounts[0]["RW"],
        "state": state["Status"],
        "exitCode": state["ExitCode"],
    }


def validate_container_execution_evidence(
    evidence: EntraCallingClientMSALZeroRetryContainerExecutionEvidence,
) -> dict[str, object]:
    if type(evidence) is not EntraCallingClientMSALZeroRetryContainerExecutionEvidence:
        raise ValueError("exact container execution evidence is required")
    evidence.__post_init__()
    image = _image_projection(evidence.image_inspect_document, evidence.image_id)
    before_identity = _json_document(
        evidence.container_inspect_before_start_document,
        MAX_INSPECT_BYTES,
        "container inspection",
    ).get("Id")
    after_identity = _json_document(
        evidence.container_inspect_after_exit_document,
        MAX_INSPECT_BYTES,
        "container inspection",
    ).get("Id")
    if before_identity != after_identity:
        raise ValueError("container identity changed across execution")
    return {
        "docker": _docker_version_projection(evidence.docker_version_document),
        "image": image,
        "before": _container_projection(
            evidence.container_inspect_before_start_document,
            image_id=evidence.image_id,
            expect_running=False,
            expected_image_environment=image["environment"],
        ),
        "after": _container_projection(
            evidence.container_inspect_after_exit_document,
            image_id=evidence.image_id,
            expect_running=True,
            expected_image_environment=image["environment"],
        ),
        "nodeExecutableSha256": evidence.node_executable_sha256,
        "commandSequence": evidence.command_sequence,
        "cleanupSucceeded": evidence.cleanup_succeeded,
    }


def _command_environment(workspace: Path) -> dict[str, str]:
    home = workspace / "docker-home"
    config = workspace / "docker-config"
    home.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    environment = {
        "DOCKER_CONFIG": str(config),
        "HOME": str(home),
        "NO_COLOR": "1",
        "TEMP": str(workspace),
        "TMP": str(workspace),
        "USERPROFILE": str(home),
    }
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot")
        if type(system_root) is not str or not os.path.isabs(system_root):
            raise ValueError("Windows system root is unavailable")
        environment["SystemRoot"] = system_root
    return environment


def _run_checked(
    docker: str,
    arguments: list[str],
    *,
    environment: dict[str, str],
    timeout: int,
    maximum_stdout: int = MAX_INSPECT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    command = [docker, *arguments]
    process = subprocess.Popen(
        command,
        cwd=environment["TEMP"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ValueError("Docker command pipes are unavailable")
    stdout_parts: list[bytes] = []
    stderr_parts: list[bytes] = []
    overflow = threading.Event()
    reader_errors: list[BaseException] = []

    def read_bounded(
        stream: Any,
        destination: list[bytes],
        maximum: int,
    ) -> None:
        total = 0
        try:
            while chunk := stream.read(65_536):
                if type(chunk) is not bytes:
                    raise ValueError("Docker command stream returned non-bytes")
                total += len(chunk)
                if total > maximum:
                    overflow.set()
                    return
                destination.append(chunk)
        except BaseException as error:  # noqa: BLE001
            reader_errors.append(error)
            overflow.set()

    readers = (
        threading.Thread(
            target=read_bounded,
            args=(process.stdout, stdout_parts, maximum_stdout),
            daemon=True,
        ),
        threading.Thread(
            target=read_bounded,
            args=(process.stderr, stderr_parts, MAX_COMMAND_STDERR_BYTES),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while process.poll() is None:
            if overflow.is_set():
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
            time.sleep(0.01)
        process.wait(timeout=5)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        raise
    finally:
        for reader in readers:
            reader.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    if any(reader.is_alive() for reader in readers):
        raise ValueError("Docker command stream reader did not terminate")
    if timed_out:
        raise TimeoutError("Docker command exceeded its wall-clock timeout")
    if overflow.is_set() or reader_errors:
        raise ValueError("Docker command exceeded its evidence bound")
    result = subprocess.CompletedProcess(
        command,
        process.returncode,
        b"".join(stdout_parts),
        b"".join(stderr_parts),
    )
    if (
        type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > maximum_stdout
        or type(result.stderr) is not bytes
        or result.stderr
        or len(result.stderr) > MAX_COMMAND_STDERR_BYTES
    ):
        raise ValueError("Docker command failed or exceeded its evidence bound")
    return result


def _write_workspace(
    request: EntraCallingClientMSALZeroRetryContainerExecutionRequest, workspace: Path
) -> None:
    files = {
        "authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs": request.adapter,
        HARNESS_FILE_NAME: request.harness,
        RUNNER_FILE_NAME: request.runner,
    }
    os.chmod(workspace, 0o755)
    for name, content in files.items():
        path = workspace / name
        path.write_bytes(content)
        os.chmod(path, 0o444)


def _create_arguments(image_id: str, workspace: Path) -> list[str]:
    cidfile = workspace.parent / "container.cid"
    values = [
        "container",
        "create",
        "--pull",
        "never",
        "--cidfile",
        str(cidfile),
        "--platform",
        f"{CONTAINER_OPERATING_SYSTEM}/{CONTAINER_ARCHITECTURE}",
        "--network",
        CONTAINER_NETWORK_MODE,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--security-opt",
        "seccomp=builtin",
        "--user",
        CONTAINER_USER,
        "--workdir",
        CONTAINER_WORKDIR,
        "--mount",
        f"type=bind,src={workspace},dst={CONTAINER_MOUNT_TARGET},readonly",
        "--pids-limit",
        str(CONTAINER_PIDS_LIMIT),
        "--memory",
        str(CONTAINER_MEMORY_BYTES),
        "--memory-swap",
        str(CONTAINER_MEMORY_SWAP_BYTES),
        "--cpus",
        f"{CONTAINER_CPUS_MILLI / 1000:.3f}",
        "--shm-size",
        str(CONTAINER_SHM_BYTES),
        "--stop-timeout",
        str(CONTAINER_STOP_TIMEOUT_SECONDS),
        "--restart",
        "no",
        "--log-driver",
        "none",
        "--no-healthcheck",
        "--pid",
        "private",
        "--ipc",
        "private",
        "--uts",
        "private",
        "--cgroupns",
        "private",
        "--entrypoint",
        CONTAINER_NODE_PATH,
    ]
    for name, value in sorted(_environment_overrides().items()):
        values.extend(("--env", f"{name}={value}"))
    values.append(image_id)
    values.extend(_container_arguments())
    return values


def _read_container_id(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 128:
        raise ValueError("Docker container ID file is invalid")
    try:
        value = path.read_bytes().decode("ascii").strip()
    except UnicodeDecodeError:
        raise ValueError("Docker container ID encoding is invalid") from None
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("Docker container ID is invalid")
    return value


def _sealed_execute(
    request: EntraCallingClientMSALZeroRetryContainerExecutionRequest,
    docker_executable_path: str,
) -> EntraCallingClientMSALZeroRetryContainerExecutionEvidence:
    docker = _validate_docker_path(
        docker_executable_path,
        request.approved_docker_executable_sha256,
    )
    container_id: str | None = None
    cleanup_succeeded = False
    captured_error: BaseException | None = None
    version = image = before = after = stdout = stderr = None
    node_digest = None
    with tempfile.TemporaryDirectory(prefix="e4m-step230-") as temporary:
        root = Path(temporary)
        workspace = root / "work"
        workspace.mkdir(mode=0o755)
        _write_workspace(request, workspace)
        environment = _command_environment(root)
        cidfile = root / "container.cid"
        try:
            version = _run_checked(
                docker,
                ["version", "--format", "{{json .Server}}"],
                environment=environment,
                timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
            ).stdout
            _docker_version_projection(version)
            image = _run_checked(
                docker,
                ["image", "inspect", "--format", "{{json .}}", request.image_id],
                environment=environment,
                timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
            ).stdout
            image_projection = _image_projection(image, request.image_id)
            cidfile_container_id: str | None = None
            try:
                created = _run_checked(
                    docker,
                    _create_arguments(request.image_id, workspace),
                    environment=environment,
                    timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
                    maximum_stdout=256,
                )
                try:
                    stdout_container_id = created.stdout.decode("ascii").strip()
                except UnicodeDecodeError:
                    raise ValueError(
                        "Docker container ID encoding is invalid"
                    ) from None
                if len(stdout_container_id) != 64 or any(
                    character not in "0123456789abcdef"
                    for character in stdout_container_id
                ):
                    raise ValueError("Docker container ID is invalid")
                container_id = stdout_container_id
            finally:
                if cidfile.is_file() and not cidfile.is_symlink():
                    cidfile_container_id = _read_container_id(cidfile)
                    if container_id is None:
                        container_id = cidfile_container_id
            if (
                container_id is None
                or cidfile_container_id is None
                or stdout_container_id != cidfile_container_id
            ):
                raise ValueError("Docker container ID evidence is inconsistent")
            before = _run_checked(
                docker,
                ["container", "inspect", "--format", "{{json .}}", container_id],
                environment=environment,
                timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
            ).stdout
            _container_projection(
                before,
                image_id=request.image_id,
                expect_running=False,
                expected_image_environment=image_projection["environment"],
                expected_container_id=container_id,
            )
            copied = root / "copied-node"
            _run_checked(
                docker,
                [
                    "container",
                    "cp",
                    f"{container_id}:{CONTAINER_NODE_PATH}",
                    str(copied),
                ],
                environment=environment,
                timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
                maximum_stdout=1024,
            )
            _hash_regular_file(
                copied,
                MAX_NODE_EXECUTABLE_BYTES,
                request.approved_node_executable_sha256,
            )
            node_digest = request.approved_node_executable_sha256
            completed = _run_checked(
                docker,
                ["container", "start", "--attach", container_id],
                environment=environment,
                timeout=CONTAINER_EXECUTION_TIMEOUT_SECONDS,
                maximum_stdout=MAXIMUM_STDOUT_BYTES,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            after = _run_checked(
                docker,
                ["container", "inspect", "--format", "{{json .}}", container_id],
                environment=environment,
                timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
            ).stdout
            _container_projection(
                after,
                image_id=request.image_id,
                expect_running=True,
                expected_image_environment=image_projection["environment"],
                expected_container_id=container_id,
            )
        except BaseException as error:  # noqa: BLE001
            captured_error = error
        finally:
            if container_id is not None:
                try:
                    removed = _run_checked(
                        docker,
                        ["container", "rm", "--force", container_id],
                        environment=environment,
                        timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
                        maximum_stdout=256,
                    )
                    cleanup_succeeded = bool(removed.stdout.strip())
                except BaseException as cleanup_error:  # noqa: BLE001
                    if captured_error is None:
                        captured_error = cleanup_error
        if captured_error is not None:
            raise captured_error
        if not all(
            type(value) is bytes
            for value in (version, image, before, after, stdout, stderr)
        ):
            raise ValueError("Docker execution evidence is incomplete")
        if node_digest is None or not cleanup_succeeded:
            raise ValueError("Docker execution attestation is incomplete")
        evidence = _attest_sealed(
            EntraCallingClientMSALZeroRetryContainerExecutionEvidence(
                docker_cli_sha256=request.approved_docker_executable_sha256,
                image_id=request.image_id,
                docker_version_document=version,
                image_inspect_document=image,
                container_inspect_before_start_document=before,
                container_inspect_after_exit_document=after,
                node_executable_sha256=node_digest,
                stdout=stdout,
                stderr=stderr,
                exit_code=0,
                command_sequence=COMMAND_SEQUENCE,
                cleanup_succeeded=True,
            )
        )
    return evidence


class EntraCallingClientMSALZeroRetryContainerExecutionLoader:
    """One-use all-sealed or all-injected Docker evidence loader."""

    def __init__(
        self,
        *,
        docker_executable_path: object = None,
        execution_transport: object = None,
    ) -> None:
        self._docker_executable_path = None
        self._execution_transport = None
        self._consumed = False
        injected = execution_transport is not None
        invalid = (
            (injected and docker_executable_path is not None)
            or (not injected and type(docker_executable_path) is not str)
            or (injected and not isinstance(execution_transport, Callable))
        )
        if not invalid:
            self._docker_executable_path = docker_executable_path
            self._execution_transport = execution_transport
        docker_executable_path = None
        execution_transport = None
        if invalid:
            raise TypeError("Docker execution loader configuration is invalid")

    def load(
        self,
        request: EntraCallingClientMSALZeroRetryContainerExecutionRequest,
    ) -> EntraCallingClientMSALZeroRetryContainerExecutionEvidence:
        result = None
        error = None
        invalid = False
        interrupted = False
        terminated = False
        try:
            result = self._load_once(request)
        except TypeError as caught:
            error = caught
            invalid = True
        except BaseException as caught:  # noqa: BLE001
            error = caught
        finally:
            request = None
            if error is not None:
                interrupted, terminated = _scrub(error)
            error = None
        if interrupted:
            raise KeyboardInterrupt("Docker execution loading interrupted")
        if terminated:
            raise SystemExit("Docker execution loading terminated")
        if invalid:
            raise TypeError("Docker execution loader input is invalid")
        if result is None:
            raise EntraCallingClientMSALZeroRetryContainerExecutionLoaderError(
                "Docker execution loading failed"
            )
        return result

    def _load_once(
        self,
        request: EntraCallingClientMSALZeroRetryContainerExecutionRequest,
    ) -> EntraCallingClientMSALZeroRetryContainerExecutionEvidence:
        if self._consumed:
            raise EntraCallingClientMSALZeroRetryContainerExecutionLoaderError(
                "Docker execution loader is already consumed"
            )
        self._consumed = True
        docker_executable_path = self._docker_executable_path
        execution_transport = self._execution_transport
        self._docker_executable_path = None
        self._execution_transport = None
        if (
            type(request)
            is not EntraCallingClientMSALZeroRetryContainerExecutionRequest
        ):
            raise TypeError("exact Docker execution request is required")
        request.__post_init__()
        injected = execution_transport is not None
        if injected:
            evidence = execution_transport(request)
        else:
            evidence = _sealed_execute(request, docker_executable_path)
        if (
            type(evidence)
            is not EntraCallingClientMSALZeroRetryContainerExecutionEvidence
        ):
            raise EntraCallingClientMSALZeroRetryContainerExecutionLoaderError(
                "exact Docker execution evidence is required"
            )
        evidence.__post_init__()
        if is_sealed_container_execution_evidence(evidence) is injected:
            raise EntraCallingClientMSALZeroRetryContainerExecutionLoaderError(
                "Docker execution evidence provenance is invalid"
            )
        return evidence


def _scrub(error: BaseException) -> tuple[bool, bool]:
    pending = [error]
    seen: set[int] = set()
    interrupted = False
    terminated = False
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        interrupted |= isinstance(current, KeyboardInterrupt)
        terminated |= isinstance(current, SystemExit)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
        except BaseException:  # noqa: BLE001, S110
            pass
    return interrupted, terminated


__all__ = [
    "COMMAND_SEQUENCE",
    "EntraCallingClientMSALZeroRetryContainerExecutionEvidence",
    "EntraCallingClientMSALZeroRetryContainerExecutionLoader",
    "EntraCallingClientMSALZeroRetryContainerExecutionLoaderError",
    "EntraCallingClientMSALZeroRetryContainerExecutionRequest",
    "EntraCallingClientMSALZeroRetryContainerExecutionTransport",
    "is_sealed_container_execution_evidence",
    "validate_container_execution_evidence",
]
