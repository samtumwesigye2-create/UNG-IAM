"""
Comprehensive test suite for service credential authentication.
Tests cover:
- Valid service credential usage
- Expired credential rejection
- Inactive identity rejection
- Permissions exposure verification
- Existing session auth behavior preserved
"""
import os
import sys
import json
import time
import uuid
from typing import Optional

# SQLite in-memory DB for testing
os.environ["UNG_IAM_DATABASE_URL"] = ""

from app import (
    app, db, now, hash_token, password_hash, payload, 
    resolve_principal, init_db, ServiceCredentialRequest
)
from fastapi.testclient import TestClient

client = TestClient(app)


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


def log(title: str, message: str, color=Colors.BLUE):
    print(f"{color}[{title}] {message}{Colors.RESET}")


def success(msg: str):
    log("✓ PASS", msg, Colors.GREEN)


def failure(msg: str):
    log("✗ FAIL", msg, Colors.RED)


def info(msg: str):
    log("INFO", msg, Colors.YELLOW)


# ============================================================================
# Test Suite 1: Service Credential Creation & Validation
# ============================================================================

def test_create_service_credential():
    """Test creating a service credential via the API."""
    info("Setting up test environment...")
    init_db()
    c = db()
    
    # Create a test admin identity
    admin_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
        (admin_id, "human", "corporate", "Test Admin", "admin@test.local",
         password_hash("TestPassword123"), now(), now()),
    )
    
    # Grant admin the necessary permissions
    admin_role = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
    c.execute("INSERT INTO identity_roles VALUES(?,?)", (admin_id, admin_role["id"]))
    
    # Create an admin session
    admin_session = "iam_" + "x" * 60
    admin_session_hash = hash_token(admin_session)
    c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)",
              (admin_session_hash, admin_id, now() + 28800, now(), now()))
    
    # Create a service identity
    service_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
        (service_id, "service", "service", "Test Service", None, None, now(), now()),
    )
    service_role = c.execute("SELECT id FROM roles WHERE name='service'").fetchone()
    c.execute("INSERT INTO identity_roles VALUES(?,?)", (service_id, service_role["id"]))
    c.commit()
    c.close()
    
    # Create credential via API
    resp = client.post(
        f"/v1/service-identities/{service_id}/credentials",
        json={"label": "Test credential", "ttl_seconds": 3600},
        headers={"Authorization": f"Bearer {admin_session}"}
    )
    
    if resp.status_code == 200:
        data = resp.json()
        if "credential" in data and data["credential"].startswith("svc_"):
            success(f"Service credential created: {data['credential'][:10]}...")
            return service_id, admin_session, admin_id
        else:
            failure(f"Missing credential in response: {data}")
            sys.exit(1)
    else:
        failure(f"Failed to create credential: {resp.status_code} {resp.text}")
        sys.exit(1)


def test_valid_service_credential_auth(service_id: str, admin_session: str, admin_id: str):
    """Test that a valid service credential can authenticate."""
    info("Testing valid service credential authentication...")
    
    c = db()
    
    # Create a new short-lived service credential
    cred_raw = "svc_" + "y" * 60
    cred_hash = hash_token(cred_raw)
    expiry = now() + 3600
    c.execute(
        "INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",
        (cred_hash, service_id, "Test token", expiry, now()),
    )
    c.commit()
    c.close()
    
    # Test using the credential to call /v1/me
    resp = client.get(
        "/v1/me",
        headers={"Authorization": f"Bearer {cred_raw}"}
    )
    
    if resp.status_code == 200:
        data = resp.json()
        if data["id"] == service_id and data["identity_type"] == "service":
            success(f"Service credential authenticated successfully")
        else:
            failure(f"Wrong identity returned: {data.get('id')}")
            sys.exit(1)
    else:
        failure(f"Authentication failed: {resp.status_code} {resp.text}")
        sys.exit(1)


def test_expired_credential_rejected(service_id: str):
    """Test that an expired service credential is rejected."""
    info("Testing expired credential rejection...")
    
    c = db()
    
    # Create an expired service credential
    expired_cred = "svc_" + "z" * 60
    expired_hash = hash_token(expired_cred)
    expiry = now() - 3600  # Already expired
    c.execute(
        "INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",
        (expired_hash, service_id, "Expired token", expiry, now()),
    )
    c.commit()
    c.close()
    
    # Try to use the expired credential
    resp = client.get(
        "/v1/me",
        headers={"Authorization": f"Bearer {expired_cred}"}
    )
    
    if resp.status_code == 401:
        success("Expired credential correctly rejected with 401")
    else:
        failure(f"Expired credential was not rejected: {resp.status_code}")
        sys.exit(1)


def test_inactive_identity_rejected(service_id: str):
    """Test that a credential for an inactive identity is rejected."""
    info("Testing inactive identity rejection...")
    
    c = db()
    
    # Deactivate the service identity
    c.execute("UPDATE identities SET is_active=0 WHERE id=?", (service_id,))
    
    # Create a credential for the now-inactive identity
    inactive_cred = "svc_" + "w" * 60
    inactive_hash = hash_token(inactive_cred)
    c.execute(
        "INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",
        (inactive_hash, service_id, "Inactive token", None, now()),
    )
    c.commit()
    c.close()
    
    # Try to use the credential
    resp = client.get(
        "/v1/me",
        headers={"Authorization": f"Bearer {inactive_cred}"}
    )
    
    if resp.status_code == 401:
        success("Inactive identity credential correctly rejected with 401")
    else:
        failure(f"Inactive identity was not rejected: {resp.status_code}")
        sys.exit(1)
    
    # Re-activate for other tests
    c = db()
    c.execute("UPDATE identities SET is_active=1 WHERE id=?", (service_id,))
    c.commit()
    c.close()


def test_permissions_exposure(admin_session: str):
    """Test that permissions are correctly exposed in identity payload."""
    info("Testing permissions exposure in identity payload...")
    
    resp = client.get(
        "/v1/me",
        headers={"Authorization": f"Bearer {admin_session}"}
    )
    
    if resp.status_code == 200:
        data = resp.json()
        if "permissions" in data and isinstance(data["permissions"], list):
            # Admin should have all permissions
            if len(data["permissions"]) > 0:
                success(f"Admin has {len(data['permissions'])} permissions exposed correctly")
            else:
                failure("Admin permissions list is empty")
                sys.exit(1)
        else:
            failure("Permissions not in response")
            sys.exit(1)
    else:
        failure(f"Failed to get identity: {resp.status_code}")
        sys.exit(1)


def test_existing_session_auth():
    """Test that existing human session authentication still works."""
    info("Testing existing session authentication...")
    
    # Create a new human identity and session
    c = db()
    human_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
        (human_id, "human", "corporate", "Test Human", "human@test.local",
         password_hash("HumanPassword123"), now(), now()),
    )
    
    # Create a session for the human
    session = "iam_" + "a" * 60
    session_hash = hash_token(session)
    c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)",
              (session_hash, human_id, now() + 28800, now(), now()))
    c.commit()
    c.close()
    
    # Test accessing /v1/me with session token
    resp = client.get(
        "/v1/me",
        headers={"Authorization": f"Bearer {session}"}
    )
    
    if resp.status_code == 200:
        data = resp.json()
        if data["id"] == human_id and data["identity_type"] == "human":
            success("Human session authentication works correctly")
        else:
            failure("Wrong identity returned from session")
            sys.exit(1)
    else:
        failure(f"Session authentication failed: {resp.status_code}")
        sys.exit(1)


def test_permission_enforcement_on_service_credential():
    """Test that service credentials can access endpoints requiring permissions."""
    info("Testing permission enforcement on service credential...")
    
    c = db()
    
    # Create a service identity with specific permissions
    svc_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
        (svc_id, "service", "service", "Limited Service", None, None, now(), now()),
    )
    
    # Create a custom role with iam:read permission
    role_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO roles VALUES(?,?,?,?)",
        (role_id, "limited-service-role", "Limited service role", now()),
    )
    c.execute("INSERT INTO role_permissions VALUES(?,?)", (role_id, "iam:read"))
    c.execute("INSERT INTO identity_roles VALUES(?,?)", (svc_id, role_id))
    
    # Create a credential for this service
    cred = "svc_" + "p" * 60
    cred_hash = hash_token(cred)
    c.execute(
        "INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",
        (cred_hash, svc_id, "Limited cred", None, now()),
    )
    c.commit()
    c.close()
    
    # Test that the credential can access iam:read endpoint
    resp = client.get(
        "/v1/identities",
        headers={"Authorization": f"Bearer {cred}"}
    )
    
    if resp.status_code == 200:
        success("Service credential with iam:read permission can access /v1/identities")
    else:
        failure(f"Permission-protected endpoint failed: {resp.status_code}")
        sys.exit(1)
    
    # Test that it cannot access iam:write endpoint
    resp = client.post(
        "/v1/identities",
        json={
            "display_name": "Test",
            "identity_type": "human",
            "access_class": "corporate",
            "email": "test@test.local",
            "password": "TestPassword123",
        },
        headers={"Authorization": f"Bearer {cred}"}
    )
    
    if resp.status_code == 403:
        success("Service credential correctly denied access to iam:write endpoint (403)")
    else:
        failure(f"Expected 403, got {resp.status_code}")
        sys.exit(1)


def test_last_used_at_updated():
    """Test that last_used_at is updated when service credential is used."""
    info("Testing last_used_at timestamp update...")
    
    c = db()
    
    # Create a service identity with a credential
    svc_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
        (svc_id, "service", "service", "Timestamp Test Service", None, None, now(), now()),
    )
    service_role = c.execute("SELECT id FROM roles WHERE name='service'").fetchone()
    c.execute("INSERT INTO identity_roles VALUES(?,?)", (svc_id, service_role["id"]))
    
    cred = "svc_" + "t" * 60
    cred_hash = hash_token(cred)
    creation_time = now()
    c.execute(
        "INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",
        (cred_hash, svc_id, "Timestamp test", None, creation_time),
    )
    c.commit()
    c.close()
    
    # Check initial last_used_at
    c = db()
    initial = c.execute(
        "SELECT last_used_at FROM service_credentials WHERE credential_hash=?",
        (cred_hash,)
    ).fetchone()
    c.close()
    
    if initial["last_used_at"] is not None:
        failure(f"last_used_at should be NULL initially, got {initial['last_used_at']}")
        sys.exit(1)
    
    # Wait a moment and use the credential
    time.sleep(0.1)
    resp = client.get(
        "/v1/me",
        headers={"Authorization": f"Bearer {cred}"}
    )
    
    if resp.status_code != 200:
        failure(f"Failed to use credential: {resp.status_code}")
        sys.exit(1)
    
    # Check that last_used_at is now set
    c = db()
    updated = c.execute(
        "SELECT last_used_at FROM service_credentials WHERE credential_hash=?",
        (cred_hash,)
    ).fetchone()
    c.close()
    
    if updated["last_used_at"] is not None and updated["last_used_at"] > creation_time:
        success(f"last_used_at correctly updated: {updated['last_used_at']}")
    else:
        failure(f"last_used_at was not updated: {updated['last_used_at']}")
        sys.exit(1)


def test_no_bearer_token_rejected():
    """Test that requests without bearer token are rejected."""
    info("Testing missing bearer token rejection...")
    
    resp = client.get("/v1/me")
    
    if resp.status_code == 401:
        success("Request without bearer token correctly rejected (401)")
    else:
        failure(f"Expected 401, got {resp.status_code}")
        sys.exit(1)


def test_invalid_token_rejected():
    """Test that invalid tokens are rejected."""
    info("Testing invalid token rejection...")
    
    resp = client.get(
        "/v1/me",
        headers={"Authorization": "Bearer invalid_token_xyz"}
    )
    
    if resp.status_code == 401:
        success("Invalid token correctly rejected (401)")
    else:
        failure(f"Expected 401, got {resp.status_code}")
        sys.exit(1)


# ============================================================================
# Main Test Runner
# ============================================================================

if __name__ == "__main__":
    print(f"\n{Colors.BLUE}{'='*70}")
    print("UNG-IAM Service Credential Authentication Test Suite")
    print(f"{'='*70}{Colors.RESET}\n")
    
    try:
        info("Starting test suite...")
        
        # Test 1: Create and retrieve service credential
        service_id, admin_session, admin_id = test_create_service_credential()
        
        # Test 2: Valid service credential authentication
        test_valid_service_credential_auth(service_id, admin_session, admin_id)
        
        # Test 3: Expired credential rejection
        test_expired_credential_rejected(service_id)
        
        # Test 4: Inactive identity rejection
        test_inactive_identity_rejected(service_id)
        
        # Test 5: Permissions exposure
        test_permissions_exposure(admin_session)
        
        # Test 6: Existing session authentication
        test_existing_session_auth()
        
        # Test 7: Permission enforcement
        test_permission_enforcement_on_service_credential()
        
        # Test 8: last_used_at update
        test_last_used_at_updated()
        
        # Test 9: No bearer token rejection
        test_no_bearer_token_rejected()
        
        # Test 10: Invalid token rejection
        test_invalid_token_rejected()
        
        print(f"\n{Colors.GREEN}{'='*70}")
        print("✓ ALL TESTS PASSED")
        print(f"{'='*70}{Colors.RESET}\n")
        
    except Exception as e:
        print(f"\n{Colors.RED}{'='*70}")
        print(f"✗ TEST SUITE FAILED: {e}")
        print(f"{'='*70}{Colors.RESET}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

