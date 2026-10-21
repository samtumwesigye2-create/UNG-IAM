import entrypoint


def test_entrypoint_has_recovery_secret_gate():
    assert hasattr(entrypoint, "RecoverySecretMiddleware")


def test_recovery_gate_rejects_missing_or_wrong_secret_in_production():
    assert entrypoint._recovery_secret_allowed("", "expected", True) is False
    assert entrypoint._recovery_secret_allowed("wrong", "expected", True) is False


def test_recovery_gate_accepts_matching_secret_and_dev_without_config():
    assert entrypoint._recovery_secret_allowed("expected", "expected", True) is True
    assert entrypoint._recovery_secret_allowed("", "", False) is True
    assert entrypoint._recovery_secret_allowed("", "", True) is False
