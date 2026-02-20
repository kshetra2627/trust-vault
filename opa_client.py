"""
opa_client.py — Open Policy Agent integration for TrustVault zero-trust enforcement.

OPA is queried before every sensitive operation. If OPA is unavailable,
the system falls back to role-based checks (fail-open with logging).
Set OPA_STRICT=true in .env to fail-closed if OPA is down.
"""

import os
import httpx
import logging
from fastapi import HTTPException

logger = logging.getLogger(__name__)

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = "/v1/data/trustvault/allow"
OPA_STRICT = os.getenv("OPA_STRICT", "false").lower() == "true"
OPA_TIMEOUT = float(os.getenv("OPA_TIMEOUT", "2.0"))


def _fallback_allow(role: str, action: str) -> bool:
    if role == "admin":
        return True
    if role == "user" and action in ["upload", "download", "delete", "list", "share", "gdpr_erase", "view_audit", "compliance_report"]:
        return True
    if role == "readonly" and action in ["download", "list", "view_audit", "compliance_report"]:
        return True
    return False


def check_policy(
    role: str,
    action: str,
    user: str = None,
    resource: str = None,
    user_region: str = None,
    storage_region: str = None,
) -> bool:
    input_data = {
        "input": {
            "role": role,
            "action": action,
            "user": user,
            "resource": resource,
            "user_region": user_region,
            "storage_region": storage_region,
        }
    }

    try:
        response = httpx.post(
            f"{OPA_URL}{OPA_POLICY_PATH}",
            json=input_data,
            timeout=OPA_TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()
        allowed = result.get("result", False)
        logger.info(
            f"OPA decision: user={user} role={role} action={action} "
            f"resource={resource} → {'ALLOW' if allowed else 'DENY'}"
        )
        return allowed

    except httpx.ConnectError:
        logger.warning(f"OPA unreachable at {OPA_URL}. Using fallback RBAC.")
        if OPA_STRICT:
            raise HTTPException(
                status_code=503,
                detail="Policy engine unavailable. Access denied in strict mode."
            )
        return _fallback_allow(role, action)

    except httpx.TimeoutException:
        logger.warning(f"OPA timeout after {OPA_TIMEOUT}s. Using fallback RBAC.")
        if OPA_STRICT:
            raise HTTPException(
                status_code=503,
                detail="Policy engine timeout. Access denied in strict mode."
            )
        return _fallback_allow(role, action)

    except Exception as e:
        logger.error(f"OPA unexpected error: {e}. Using fallback RBAC.")
        if OPA_STRICT:
            raise HTTPException(status_code=503, detail=f"Policy engine error: {str(e)}")
        return _fallback_allow(role, action)


def enforce_policy(
    role: str,
    action: str,
    user: str = None,
    resource: str = None,
    user_region: str = None,
    storage_region: str = None,
):
    allowed = check_policy(
        role=role,
        action=action,
        user=user,
        resource=resource,
        user_region=user_region,
        storage_region=storage_region,
    )
    if not allowed:
        logger.warning(
            f"ACCESS DENIED: user={user} role={role} action={action} resource={resource}"
        )
        raise HTTPException(
            status_code=403,
            detail=f"Access denied by policy engine: '{action}' not permitted for role '{role}'"
        )


def check_data_residency(user_region: str, storage_region: str) -> bool:
    input_data = {
        "input": {
            "user_region": user_region,
            "storage_region": storage_region,
        }
    }
    try:
        response = httpx.post(
            f"{OPA_URL}/v1/data/trustvault/data_region_valid",
            json=input_data,
            timeout=OPA_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("result", True)
    except Exception:
        if user_region == "EU" and storage_region != "EU":
            return False
        return True


def get_opa_health() -> dict:
    try:
        response = httpx.get(f"{OPA_URL}/health", timeout=OPA_TIMEOUT)
        return {
            "status": "healthy" if response.status_code == 200 else "degraded",
            "url": OPA_URL,
            "strict_mode": OPA_STRICT,
        }
    except Exception as e:
        return {
            "status": "unreachable",
            "url": OPA_URL,
            "strict_mode": OPA_STRICT,
            "error": str(e),
        }