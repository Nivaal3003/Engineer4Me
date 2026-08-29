from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_execution_loader as module
import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_isolation_readiness as step229
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    HARNESS_FILE_NAME,
    RUNNER_FILE_NAME,
)

SECURITY = Path(__file__).parents[1] / "app/security"
ADAPTER = (
    SECURITY
    / "authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs"
)
HARNESS = SECURITY / HARNESS_FILE_NAME
RUNNER = SECURITY / RUNNER_FILE_NAME
IMAGE_ID = "sha256:" + "2" * 64
DOCKER_SHA256 = "3" * 64
NODE_SHA256 = "1" * 64
CONTAINER_ID = "4" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _version() -> bytes:
    return _canonical(
        {
            "ApiVersion": "1.53",
            "Arch": "amd64",
            "Os": "linux",
            "Version": "29.6.1",
        }
    )


def _image(**updates: object) -> bytes:
    value: dict[str, object] = {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": "amd64",
        "Size": 100_000_000,
        "Config": {
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION=24.19.0",
                "YARN_VERSION=1.22.22",
            ],
            "Volumes": None,
            "ExposedPorts": None,
            "Healthcheck": None,
            "OnBuild": None,
        },
        "RootFS": {"Type": "layers", "Layers": ["sha256:" + "5" * 64]},
    }
    value.update(updates)
    return _canonical(value)


def _container(*, exited: bool, **updates: object) -> bytes:
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "NODE_VERSION": "24.19.0",
        "YARN_VERSION": "1.22.22",
        **module._environment_overrides(),
    }
    value: dict[str, object] = {
        "Id": CONTAINER_ID,
        "Image": IMAGE_ID,
        "Path": step229.CONTAINER_NODE_PATH,
        "Args": list(module._container_arguments()),
        "Config": {
            "Image": IMAGE_ID,
            "User": step229.CONTAINER_USER,
            "WorkingDir": step229.CONTAINER_WORKDIR,
            "Entrypoint": [step229.CONTAINER_NODE_PATH],
            "Cmd": list(module._container_arguments()),
            "Env": [f"{name}={value}" for name, value in sorted(environment.items())],
            "Healthcheck": {"Test": ["NONE"]},
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "PidsLimit": 32,
            "Memory": 268_435_456,
            "MemorySwap": 268_435_456,
            "NanoCpus": 1_000_000_000,
            "ShmSize": 16_777_216,
            "AutoRemove": False,
            "PublishAllPorts": False,
            "PortBindings": {},
            "Devices": [],
            "Binds": None,
            "Tmpfs": {},
            "VolumesFrom": None,
            "Links": None,
            "ExtraHosts": None,
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "PidMode": "private",
            "IpcMode": "private",
            "UTSMode": "private",
            "CgroupnsMode": "private",
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "LogConfig": {"Type": "none", "Config": {}},
            "SecurityOpt": ["no-new-privileges=true", "seccomp=builtin"],
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/host/ephemeral/work",
                "Destination": "/work",
                "RW": False,
            }
        ],
        "NetworkSettings": {
            "Networks": {
                "none": {
                    "Gateway": "",
                    "IPAddress": "",
                    "GlobalIPv6Address": "",
                }
            },
            "Ports": {},
        },
        "State": (
            {
                "Running": False,
                "Status": "exited",
                "ExitCode": 0,
                "StartedAt": "2026-08-17T00:00:00Z",
                "FinishedAt": "2026-08-17T00:00:01Z",
            }
            if exited
            else {"Running": False, "Status": "created", "ExitCode": 0}
        ),
    }
    value.update(updates)
    return _canonical(value)


def _request(**updates: object):
    values: dict[str, object] = {
        "image_id": IMAGE_ID,
        "approved_docker_executable_sha256": DOCKER_SHA256,
        "approved_node_executable_sha256": NODE_SHA256,
        "adapter": ADAPTER.read_bytes(),
        "harness": HARNESS.read_bytes(),
        "runner": RUNNER.read_bytes(),
    }
    values.update(updates)
    return module.EntraCallingClientMSALZeroRetryContainerExecutionRequest(**values)


def _evidence(**updates: object):
    values: dict[str, object] = {
        "docker_cli_sha256": DOCKER_SHA256,
        "image_id": IMAGE_ID,
        "docker_version_document": _version(),
        "image_inspect_document": _image(),
        "container_inspect_before_start_document": _container(exited=False),
        "container_inspect_after_exit_document": _container(exited=True),
        "node_executable_sha256": NODE_SHA256,
        "stdout": step229._step228_synthetic_stdout(),
        "stderr": b"",
        "exit_code": 0,
        "command_sequence": module.COMMAND_SEQUENCE,
        "cleanup_succeeded": True,
    }
    values.update(updates)
    return module.EntraCallingClientMSALZeroRetryContainerExecutionEvidence(**values)


def _unsafe_clone(value: object, name: str, replacement: object):
    clone = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            clone,
            item.name,
            replacement if item.name == name else getattr(value, item.name),
        )
    return clone


def test_valid_injected_loader_is_synthetic_and_one_shot() -> None:
    loader = module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        execution_transport=lambda _request: _evidence()
    )
    evidence = loader.load(_request())
    assert module.is_sealed_container_execution_evidence(evidence) is False
    projection = module.validate_container_execution_evidence(evidence)
    assert projection["docker"]["version"] == "29.6.1"
    assert projection["image"]["layers"] == ("sha256:" + "5" * 64,)
    assert projection["before"]["state"] == "created"
    assert projection["after"]["state"] == "exited"
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionLoaderError
    ):
        loader.load(_request())


def test_execution_evidence_rejects_container_identity_change() -> None:
    changed = json.loads(_container(exited=True))
    changed["Id"] = "6" * 64
    with pytest.raises(ValueError):
        module.validate_container_execution_evidence(
            _evidence(container_inspect_after_exit_document=_canonical(changed))
        )


def _install_fake_docker_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_start: bool = False,
    invalid_cidfile: bool = False,
) -> list[str]:
    calls: list[str] = []
    inspect_count = 0

    monkeypatch.setattr(module, "_validate_docker_path", lambda _path, _sha: "/docker")

    def validate_file(path: Path, _maximum: int, expected: str) -> None:
        assert path.read_bytes() == b"node-binary"
        assert expected == NODE_SHA256

    monkeypatch.setattr(module, "_hash_regular_file", validate_file)

    def run(
        _docker: str,
        arguments: list[str],
        *,
        environment: dict[str, str],
        timeout: int,
        maximum_stdout: int = module.MAX_INSPECT_BYTES,
    ):
        nonlocal inspect_count
        assert environment["DOCKER_CONFIG"]
        assert timeout in {
            module.DOCKER_COMMAND_TIMEOUT_SECONDS,
            step229.CONTAINER_EXECUTION_TIMEOUT_SECONDS,
        }
        assert maximum_stdout > 0
        if arguments[:2] == ["version", "--format"]:
            calls.append("docker_version")
            stdout = _version()
        elif arguments[:2] == ["image", "inspect"]:
            calls.append("image_inspect")
            stdout = _image()
        elif arguments[:2] == ["container", "create"]:
            calls.append("container_create")
            cidfile = Path(arguments[arguments.index("--cidfile") + 1])
            cidfile.write_text("invalid" if invalid_cidfile else CONTAINER_ID)
            stdout = (CONTAINER_ID + "\n").encode()
        elif arguments[:2] == ["container", "inspect"]:
            inspect_count += 1
            calls.append(
                "container_inspect_before_start"
                if inspect_count == 1
                else "container_inspect_after_exit"
            )
            stdout = _container(exited=inspect_count == 2)
        elif arguments[:2] == ["container", "cp"]:
            calls.append("node_binary_copy")
            Path(arguments[-1]).write_bytes(b"node-binary")
            stdout = b""
        elif arguments[:3] == ["container", "start", "--attach"]:
            calls.append("container_start_attach")
            if fail_start:
                raise ValueError("private-start-failure")
            stdout = step229._step228_synthetic_stdout()
        elif arguments[:3] == ["container", "rm", "--force"]:
            calls.append("container_remove_finally")
            stdout = (CONTAINER_ID + "\n").encode()
        else:
            raise AssertionError(arguments)
        return module.subprocess.CompletedProcess(arguments, 0, stdout, b"")

    monkeypatch.setattr(module, "_run_checked", run)
    return calls


def test_sealed_lifecycle_attests_only_after_exact_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_fake_docker_lifecycle(monkeypatch)
    loader = module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        docker_executable_path="/docker"
    )
    evidence = loader.load(_request())
    assert module.is_sealed_container_execution_evidence(evidence) is True
    assert tuple(calls) == module.COMMAND_SEQUENCE
    assert evidence.cleanup_succeeded is True


def test_sealed_lifecycle_removes_container_after_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_fake_docker_lifecycle(monkeypatch, fail_start=True)
    loader = module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        docker_executable_path="/docker"
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionLoaderError
    ):
        loader.load(_request())
    assert calls[-1] == "container_remove_finally"
    assert calls.count("container_start_attach") == 1


def test_sealed_lifecycle_uses_stdout_id_to_remove_after_cidfile_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_fake_docker_lifecycle(monkeypatch, invalid_cidfile=True)
    loader = module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        docker_executable_path="/docker"
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionLoaderError
    ):
        loader.load(_request())
    assert calls[-1] == "container_remove_finally"


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("image_id", "node:24.19.0"),
        ("approved_docker_executable_sha256", "x"),
        ("approved_node_executable_sha256", "x"),
        ("adapter", b"changed"),
        ("harness", b"changed"),
        ("runner", b"changed"),
    ],
)
def test_request_identity_tampering_fails(name: str, replacement: object) -> None:
    with pytest.raises(ValueError):
        _request(**{name: replacement})


def test_request_byte_objects_must_be_distinct() -> None:
    shared = ADAPTER.read_bytes()
    with pytest.raises(ValueError):
        _request(adapter=shared, harness=shared, runner=shared)


@pytest.mark.parametrize(
    "updates",
    [
        {"Id": "sha256:" + "0" * 64},
        {"Os": "windows"},
        {"Architecture": "arm64"},
        {"Size": True},
        {"Config": {"Env": ["NODE_VERSION=24.19.0"]}},
        {
            "Config": {
                "Env": ["PATH=/bin", "NODE_VERSION=24.19.0", "LD_PRELOAD=x"],
                "Volumes": None,
                "ExposedPorts": None,
                "Healthcheck": None,
                "OnBuild": None,
            }
        },
        {"RootFS": {"Type": "layers", "Layers": []}},
        {"RootFS": {"Type": "layers", "Layers": ["not-a-layer"]}},
    ],
)
def test_image_projection_rejects_tampering(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        module._image_projection(_image(**updates), IMAGE_ID)


@pytest.mark.parametrize(
    ("section", "name", "value"),
    [
        ("HostConfig", "NetworkMode", "bridge"),
        ("HostConfig", "ReadonlyRootfs", False),
        ("HostConfig", "Privileged", True),
        ("HostConfig", "CapDrop", []),
        ("HostConfig", "SecurityOpt", ["seccomp=unconfined"]),
        ("HostConfig", "PidsLimit", True),
        ("HostConfig", "PortBindings", {"80/tcp": {}}),
        ("Config", "User", "0:0"),
        ("Config", "Healthcheck", None),
        ("Config", "Env", ["LD_PRELOAD=/evil.so"]),
        ("State", "Status", "running"),
    ],
)
def test_container_projection_rejects_tampering(
    section: str,
    name: str,
    value: object,
) -> None:
    raw = json.loads(_container(exited=section == "State"))
    raw[section][name] = value
    with pytest.raises(ValueError):
        module._container_projection(
            _canonical(raw),
            image_id=IMAGE_ID,
            expect_running=section == "State",
            expected_image_environment={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION": "24.19.0",
                "YARN_VERSION": "1.22.22",
            },
        )


def test_container_projection_rejects_extra_mount_and_network_address() -> None:
    raw = json.loads(_container(exited=False))
    raw["Mounts"].append(copy.deepcopy(raw["Mounts"][0]))
    with pytest.raises(ValueError):
        module._container_projection(
            _canonical(raw),
            image_id=IMAGE_ID,
            expect_running=False,
            expected_image_environment={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION": "24.19.0",
                "YARN_VERSION": "1.22.22",
            },
        )
    raw = json.loads(_container(exited=False))
    raw["Id"] = "not-an-id"
    with pytest.raises(ValueError):
        module._container_projection(
            _canonical(raw),
            image_id=IMAGE_ID,
            expect_running=False,
            expected_image_environment={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION": "24.19.0",
                "YARN_VERSION": "1.22.22",
            },
        )
    raw = json.loads(_container(exited=False))
    raw["NetworkSettings"]["Networks"]["none"]["IPAddress"] = "172.17.0.2"
    with pytest.raises(ValueError):
        module._container_projection(
            _canonical(raw),
            image_id=IMAGE_ID,
            expect_running=False,
            expected_image_environment={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION": "24.19.0",
                "YARN_VERSION": "1.22.22",
            },
        )


@pytest.mark.parametrize("name", ["CapAdd", "DeviceRequests", "Sysctls"])
def test_container_projection_rejects_extra_privilege_surfaces(name: str) -> None:
    raw = json.loads(_container(exited=False))
    raw["HostConfig"][name] = ["SYS_ADMIN"] if name != "Sysctls" else {"x": "1"}
    with pytest.raises(ValueError):
        module._container_projection(
            _canonical(raw),
            image_id=IMAGE_ID,
            expect_running=False,
            expected_image_environment={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION": "24.19.0",
                "YARN_VERSION": "1.22.22",
            },
        )


def test_create_arguments_are_exact_fail_closed_profile(tmp_path: Path) -> None:
    arguments = module._create_arguments(IMAGE_ID, tmp_path)
    assert arguments[:3] == ["container", "create", "--pull"]
    assert "never" in arguments
    assert arguments.count("--network") == 1
    assert arguments[arguments.index("--network") + 1] == "none"
    assert arguments.count("--mount") == 1
    assert arguments.count("--security-opt") == 2
    assert "seccomp=builtin" in arguments
    assert "no-new-privileges=true" in arguments
    assert "--no-healthcheck" in arguments
    assert arguments[arguments.index("--cidfile") + 1] == str(
        tmp_path.parent / "container.cid"
    )
    assert arguments[arguments.index("--log-driver") + 1] == "none"
    assert "--privileged" not in arguments
    assert "--publish" not in arguments
    assert IMAGE_ID in arguments
    assert not any("registry" in value or ":latest" in value for value in arguments)


def test_bounded_process_runner_success_and_fail_closed(tmp_path: Path) -> None:
    environment = {"TEMP": str(tmp_path)}
    success = module._run_checked(
        sys.executable,
        ["-c", "import sys;sys.stdout.buffer.write(b'ok')"],
        environment=environment,
        timeout=5,
        maximum_stdout=2,
    )
    assert success.stdout == b"ok"
    with pytest.raises(ValueError):
        module._run_checked(
            sys.executable,
            ["-c", "import sys;sys.stdout.buffer.write(b'xxx')"],
            environment=environment,
            timeout=5,
            maximum_stdout=2,
        )
    with pytest.raises(ValueError):
        module._run_checked(
            sys.executable,
            ["-c", "raise SystemExit(3)"],
            environment=environment,
            timeout=5,
        )
    with pytest.raises(ValueError):
        module._run_checked(
            sys.executable,
            ["-c", "import sys;sys.stderr.write('warning')"],
            environment=environment,
            timeout=5,
        )


def test_bounded_process_runner_timeout(tmp_path: Path) -> None:
    with pytest.raises(TimeoutError):
        module._run_checked(
            sys.executable,
            ["-c", "import time;time.sleep(2)"],
            environment={"TEMP": str(tmp_path)},
            timeout=1,
        )


def test_docker_executable_and_container_id_file_are_exact(tmp_path: Path) -> None:
    executable = tmp_path / "docker-test"
    executable.write_bytes(b"exact-docker")
    os.chmod(executable, 0o755)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert module._validate_docker_path(str(executable), digest) == str(executable)
    cidfile = tmp_path / "container.cid"
    cidfile.write_text(CONTAINER_ID + "\n")
    assert module._read_container_id(cidfile) == CONTAINER_ID
    cidfile.write_text("not-an-id")
    with pytest.raises(ValueError):
        module._read_container_id(cidfile)


def test_injected_transport_cannot_confer_sealed_attestation() -> None:
    loader = module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        execution_transport=lambda _request: module._attest_sealed(_evidence())
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionLoaderError
    ):
        loader.load(_request())


@pytest.mark.parametrize(
    "values",
    [
        {"docker_executable_path": None, "execution_transport": None},
        {"docker_executable_path": "/docker", "execution_transport": lambda _: None},
        {"execution_transport": object()},
    ],
)
def test_loader_modes_are_exact(values: dict[str, object]) -> None:
    with pytest.raises(TypeError):
        module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(**values)


def test_every_evidence_field_is_guarded() -> None:
    evidence = _evidence()
    for item in fields(evidence):
        if item.name == "_sealed_attestation":
            continue
        current = getattr(evidence, item.name)
        if type(current) is bool:
            replacement: object = not current
        elif type(current) is int:
            replacement = True
        elif type(current) is bytes:
            replacement = b"x" if current == b"" else b""
        elif type(current) is tuple:
            replacement = tuple(reversed(current))
        else:
            replacement = "x"
        clone = _unsafe_clone(evidence, item.name, replacement)
        with pytest.raises(ValueError):
            clone.__post_init__()


def test_nested_interrupt_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    child = ValueError("private-docker-marker")
    group = BaseExceptionGroup(
        "private-group-marker",
        [SystemExit("private-exit"), KeyboardInterrupt("private-interrupt"), child],
    )

    def fail(_request: object) -> None:
        raise group

    loader = module.EntraCallingClientMSALZeroRetryContainerExecutionLoader(
        execution_transport=fail
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        loader.load(_request())
    assert "private" not in str(caught.value)
    assert caught.value.__context__ is None
    assert child.args == ()


def test_public_export_set_is_exact() -> None:
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "COMMAND_SEQUENCE",
        "EntraCallingClientMSALZeroRetryContainerExecutionEvidence",
        "EntraCallingClientMSALZeroRetryContainerExecutionLoader",
        "EntraCallingClientMSALZeroRetryContainerExecutionLoaderError",
        "EntraCallingClientMSALZeroRetryContainerExecutionRequest",
        "EntraCallingClientMSALZeroRetryContainerExecutionTransport",
        "is_sealed_container_execution_evidence",
        "validate_container_execution_evidence",
    }
