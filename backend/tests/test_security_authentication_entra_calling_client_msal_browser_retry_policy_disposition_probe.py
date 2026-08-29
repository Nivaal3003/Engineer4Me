from __future__ import annotations

import hashlib
import io
import json
import tarfile
from builtins import BaseExceptionGroup
from dataclasses import fields

import pytest

import app.security.authentication_entra_calling_client_msal_browser_retry_policy_disposition_probe as module
from app.security.authentication_entra_calling_client_msal_browser_retry_policy_disposition_probe import (
    EntraCallingClientMSALCompiledCallGraphEvidence,
    EntraCallingClientMSALRetryPolicyDispositionProbeError,
    EntraCallingClientMSALRetryPolicyDispositionReceipt,
    load_entra_calling_client_msal_retry_policy_disposition_proof,
    render_entra_calling_client_msal_retry_policy_disposition_receipt,
)


def _step224_document() -> bytes:
    value = {
        "document_type": (
            "engineer4me_microsoft_entra_calling_client_msal_retry_exception_decision_readiness"
        ),
        "schema_version": 1,
        "source": (
            "engineer4me_reviewed_msal_5_18_0_compiled_post_call_site_confinement"
        ),
        "approved_step223_package_manifest_sha256": (
            "3d810f2f3bcd294acaef2c4066b5fef20f95de2c053ad03cfe4f3bc6e5a485f1"
        ),
        "decision_profile": (
            "engineer4me_msal_5_18_0_retry_exception_decision_readiness_v1"
        ),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _approved_step224_digest() -> str:
    from app.security.authentication_entra_calling_client_msal_browser_retry_exception_decision_readiness import (
        load_entra_calling_client_msal_retry_exception_decision_readiness,
    )

    return load_entra_calling_client_msal_retry_exception_decision_readiness(
        _step224_document()
    ).decision_document_sha256


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step224_decision_document_sha256": _approved_step224_digest(),
        "disposition_profile": module.PROFILE,
    }
    value.update(updates)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _evidence(*, live: bool = False) -> EntraCallingClientMSALCompiledCallGraphEvidence:
    return EntraCallingClientMSALCompiledCallGraphEvidence(
        browser_dist_mjs_count=module.BROWSER_DIST_MJS_COUNT,
        browser_dist_mjs_bytes=module.BROWSER_DIST_MJS_BYTES,
        common_dist_mjs_count=module.COMMON_DIST_MJS_COUNT,
        common_dist_mjs_bytes=module.COMMON_DIST_MJS_BYTES,
        call_site_file_count=module.CALL_SITE_FILE_COUNT,
        real_invocation_file_count=module.REAL_INVOCATION_FILE_COUNT,
        fetch_client_sha256=module.FETCH_CLIENT_SHA256,
        token_call_site_sha256=module.TOKEN_CALL_SITE_SHA256,
        client_configuration_stub_sha256=module.CLIENT_CONFIGURATION_STUB_SHA256,
        network_interface_sha256=module.NETWORK_INTERFACE_SHA256,
        fetch_client_raw_occurrence_count=module.FETCH_CLIENT_RAW_OCCURRENCE_COUNT,
        token_raw_occurrence_count=module.TOKEN_RAW_OCCURRENCE_COUNT,
        client_configuration_raw_occurrence_count=(
            module.CLIENT_CONFIGURATION_RAW_OCCURRENCE_COUNT
        ),
        network_interface_raw_occurrence_count=(
            module.NETWORK_INTERFACE_RAW_OCCURRENCE_COUNT
        ),
        token_endpoint_argument_observed=True,
        fetch_client_url_guard_observed=False,
        live_exact_artifacts_attested=live,
        live_complete_dist_mjs_scan_attested=live,
    )


def _receipt() -> EntraCallingClientMSALRetryPolicyDispositionReceipt:
    return load_entra_calling_client_msal_retry_policy_disposition_proof(
        document_bytes=_document(),
        step224_document_bytes=_step224_document(),
        call_graph_transport=lambda: _evidence(),
    )


def test_synthetic_contract_rejects_exception_fail_closed() -> None:
    receipt = _receipt()
    assert receipt.policy_disposition == module.POLICY_DISPOSITION
    assert receipt.retry_exception_rejected is True
    assert receipt.zero_retry_candidate_required is True
    assert receipt.step216_zero_retry_requirement_authoritative is True
    assert receipt.retry_exception_approved is False
    assert receipt.msal_browser_5_18_0_compatible is False
    assert receipt.msal_browser_5_18_0_selected is False


def test_exact_compiled_inventory_and_call_semantics_are_bound() -> None:
    receipt = _receipt()
    assert receipt.browser_dist_mjs_count == 183
    assert receipt.browser_dist_mjs_bytes == 880_592
    assert receipt.common_dist_mjs_count == 69
    assert receipt.common_dist_mjs_bytes == 392_662
    assert receipt.call_site_file_count == 4
    assert receipt.real_invocation_file_count == 1
    assert receipt.raw_symbol_occurrence_count == 5
    assert receipt.real_invocation_passes_token_endpoint_validated is True
    assert receipt.fetch_client_method_remains_url_agnostic is True


def test_synthetic_provenance_has_zero_sealed_counts() -> None:
    receipt = _receipt()
    assert receipt.synthetic_evidence_used is True
    assert receipt.sealed_registry_request_count == 0
    assert receipt.sealed_artifact_scan_count == 0
    assert receipt.sealed_registry_reads_attested is False
    assert receipt.sealed_exact_artifacts_attested is False
    assert receipt.sealed_complete_dist_mjs_scan_attested is False
    assert receipt.injected_transport_side_effects_checked is False


def test_step224_source_document_is_rerun_and_receipt_is_not_provenance() -> None:
    receipt = _receipt()
    assert receipt.step224_source_document_revalidated is True
    assert receipt.approved_step224_digest_bound is True
    assert receipt.step224_rendered_receipt_accepted_as_provenance is False
    assert receipt.step224_decision_document_sha256 == _approved_step224_digest()


def test_domain_separated_projections_are_unique() -> None:
    receipt = _receipt()
    values = {
        receipt.complete_call_graph_projection_sha256,
        receipt.policy_rationale_sha256,
        receipt.required_successor_state_sha256,
    }
    assert len(values) == 3
    assert all(len(value) == 64 and value == value.lower() for value in values)


@pytest.mark.parametrize(
    "update",
    [
        {"document_type": "wrong"},
        {"schema_version": 2},
        {"source": "wrong"},
        {"disposition_profile": "wrong"},
        {"approved_step224_decision_document_sha256": "0" * 64},
        {"extra": True},
    ],
)
def test_disposition_document_tampering_is_rejected(update: dict[str, object]) -> None:
    with pytest.raises(EntraCallingClientMSALRetryPolicyDispositionProbeError):
        load_entra_calling_client_msal_retry_policy_disposition_proof(
            document_bytes=_document(**update),
            step224_document_bytes=_step224_document(),
            call_graph_transport=lambda: _evidence(),
        )


def test_step224_source_tampering_is_rejected() -> None:
    value = json.loads(_step224_document())
    value["approved_step223_package_manifest_sha256"] = "0" * 64
    with pytest.raises(EntraCallingClientMSALRetryPolicyDispositionProbeError):
        load_entra_calling_client_msal_retry_policy_disposition_proof(
            document_bytes=_document(),
            step224_document_bytes=json.dumps(value).encode(),
            call_graph_transport=lambda: _evidence(),
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"document_bytes": None, "step224_document_bytes": b"{}"},
        {"document_bytes": b"{}", "step224_document_bytes": None},
        {
            "document_bytes": b"{}",
            "step224_document_bytes": b"{}",
            "call_graph_transport": object(),
        },
    ],
)
def test_public_argument_types_are_sanitized(arguments: dict[str, object]) -> None:
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_msal_retry_policy_disposition_proof(**arguments)


@pytest.mark.parametrize("value", [b"", b"{", b"[]", b"\xff"])
def test_malformed_disposition_document_is_sanitized(value: bytes) -> None:
    with pytest.raises(
        EntraCallingClientMSALRetryPolicyDispositionProbeError,
        match="proof failed",
    ) as caught:
        load_entra_calling_client_msal_retry_policy_disposition_proof(
            document_bytes=value,
            step224_document_bytes=_step224_document(),
            call_graph_transport=lambda: _evidence(),
        )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_injected_evidence_requires_exact_type() -> None:
    with pytest.raises(EntraCallingClientMSALRetryPolicyDispositionProbeError):
        load_entra_calling_client_msal_retry_policy_disposition_proof(
            document_bytes=_document(),
            step224_document_bytes=_step224_document(),
            call_graph_transport=lambda: object(),
        )


def test_injected_evidence_cannot_claim_live_attestation() -> None:
    with pytest.raises(EntraCallingClientMSALRetryPolicyDispositionProbeError):
        load_entra_calling_client_msal_retry_policy_disposition_proof(
            document_bytes=_document(),
            step224_document_bytes=_step224_document(),
            call_graph_transport=lambda: _evidence(live=True),
        )


def test_live_receipt_partition_is_constructible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Artifacts:
        browser_tarball = b"browser"
        common_tarball = b"common"

    class Loader:
        def load(self, plan: object) -> tuple[object, ...]:
            assert plan == ("plan",)
            return ("responses",)

    monkeypatch.setattr(
        module,
        "build_entra_calling_client_msal_compiled_retry_live_request_plan",
        lambda: ("plan",),
    )
    monkeypatch.setattr(
        module, "BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader", Loader
    )
    monkeypatch.setattr(
        module.step223_probe, "_verify_live_responses", lambda _: Artifacts()
    )
    monkeypatch.setattr(
        module, "_scan_exact_artifacts", lambda *_: _evidence(live=True)
    )
    receipt = load_entra_calling_client_msal_retry_policy_disposition_proof(
        document_bytes=_document(),
        step224_document_bytes=_step224_document(),
    )
    assert receipt.synthetic_evidence_used is False
    assert receipt.sealed_registry_request_count == 4
    assert receipt.sealed_artifact_scan_count == 2
    assert receipt.sealed_registry_reads_attested is True
    assert receipt.sealed_exact_artifacts_attested is True
    assert receipt.sealed_complete_dist_mjs_scan_attested is True


def _tar(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def test_archive_scanner_counts_complete_dist_mjs_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = b"const sendPostRequestAsync = 1;"
    second = b"const other = 2;"
    monkeypatch.setattr(module, "BROWSER_DIST_MJS_COUNT", 2)
    monkeypatch.setattr(module, "BROWSER_DIST_MJS_BYTES", len(first) + len(second))
    count, size, hits = module._scan_archive(
        _tar(
            {
                "package/dist/one.mjs": first,
                "package/dist/two.mjs": second,
                "package/lib/ignored.mjs": b"sendPostRequestAsync",
                "package/dist/ignored.js": b"sendPostRequestAsync",
            }
        ),
        module.BROWSER_PACKAGE_NAME,
    )
    assert (count, size) == (2, len(first) + len(second))
    assert hits == {"package/dist/one.mjs": first}


def test_archive_scanner_rejects_closure_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "BROWSER_DIST_MJS_COUNT", 2)
    monkeypatch.setattr(module, "BROWSER_DIST_MJS_BYTES", 2)
    with pytest.raises(ValueError, match="closure changed"):
        module._scan_archive(
            _tar({"package/dist/one.mjs": b"x"}), module.BROWSER_PACKAGE_NAME
        )


def test_exact_artifact_scanner_binds_paths_hashes_and_token_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetch = b"sendPostRequestAsync"
    token = (
        b"sendPostRequestAsync\n" + module._TOKEN_INVOCATION + b"sendPostRequestAsync"
    )
    stub = b"sendPostRequestAsync"
    interface = b"sendPostRequestAsync"
    monkeypatch.setattr(
        module, "FETCH_CLIENT_SHA256", hashlib.sha256(fetch).hexdigest()
    )
    monkeypatch.setattr(
        module, "TOKEN_CALL_SITE_SHA256", hashlib.sha256(token).hexdigest()
    )
    monkeypatch.setattr(
        module, "CLIENT_CONFIGURATION_STUB_SHA256", hashlib.sha256(stub).hexdigest()
    )
    monkeypatch.setattr(
        module, "NETWORK_INTERFACE_SHA256", hashlib.sha256(interface).hexdigest()
    )

    def scan(_: bytes, package: str) -> tuple[int, int, dict[str, bytes]]:
        if package == module.BROWSER_PACKAGE_NAME:
            return 183, 880_592, {module.FETCH_CLIENT_PATH: fetch}
        return (
            69,
            392_662,
            {
                module.TOKEN_CALL_SITE_PATH: token,
                module.CLIENT_CONFIGURATION_STUB_PATH: stub,
                module.NETWORK_INTERFACE_PATH: interface,
            },
        )

    monkeypatch.setattr(module, "_scan_archive", scan)
    evidence = module._scan_exact_artifacts(b"browser", b"common")
    assert evidence.call_site_file_count == 4
    assert evidence.token_endpoint_argument_observed is True
    assert evidence.live_exact_artifacts_attested is True


def test_exact_artifact_scanner_rejects_wrong_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "_scan_archive",
        lambda *_: (1, 1, {"package/dist/unexpected.mjs": b"sendPostRequestAsync"}),
    )
    with pytest.raises(ValueError, match="inventory changed"):
        module._scan_exact_artifacts(b"browser", b"common")


def test_keyboard_interrupt_and_system_exit_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for error_type, expected in (
        (KeyboardInterrupt, "interrupted"),
        (SystemExit, "terminated"),
    ):

        def fail(exception: type[BaseException] = error_type, **_: object) -> object:
            raise exception("secret")

        monkeypatch.setattr(module, "_load_internal", fail)
        with pytest.raises(error_type, match=expected) as caught:
            load_entra_calling_client_msal_retry_policy_disposition_proof(secret="x")
        assert "secret" not in repr(caught.value)


def test_nested_control_flow_prefers_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_: object) -> object:
        raise BaseExceptionGroup(
            "secret", [SystemExit("secret"), KeyboardInterrupt("secret")]
        )

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt, match="interrupted"):
        load_entra_calling_client_msal_retry_policy_disposition_proof(secret="x")


def test_renderer_is_canonical_complete_and_revalidates() -> None:
    receipt = _receipt()
    rendered = render_entra_calling_client_msal_retry_policy_disposition_receipt(
        receipt
    )
    value = json.loads(rendered)
    assert list(value) == sorted(value)
    assert set(value) == {field.name for field in fields(receipt)}
    assert " " not in rendered and "\n" not in rendered


@pytest.mark.parametrize("value", [None, {}, object()])
def test_renderer_requires_exact_receipt(value: object) -> None:
    with pytest.raises(TypeError, match="exact MSAL retry-policy"):
        render_entra_calling_client_msal_retry_policy_disposition_receipt(value)  # type: ignore[arg-type]


def _invalid(name: str, value: object) -> object:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return True
    if name.endswith("sha256"):
        return "z" * 64
    return "tampered"


def test_every_receipt_field_is_guarded() -> None:
    receipt = _receipt()
    for field in fields(receipt):
        tampered = object.__new__(type(receipt))
        for candidate in fields(receipt):
            value = getattr(receipt, candidate.name)
            if candidate.name == field.name:
                value = _invalid(candidate.name, value)
            object.__setattr__(tampered, candidate.name, value)
        with pytest.raises(ValueError):
            tampered.__post_init__()
