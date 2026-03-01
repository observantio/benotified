"""
Tests for legacy plaintext secret migration helpers.
"""

from cryptography.fernet import Fernet

from services.alerting.secret_migration import migrate_tenant_settings_payload


def test_migrates_plaintext_jira_and_integration_secrets():
    fernet = Fernet(Fernet.generate_key())
    settings = {
        "jira": {
            "api_token": "plain-api-token",
            "bearer": "plain-bearer",
        },
        "jira_integrations": [
            {"apiToken": "plain-api-token-2", "bearerToken": "plain-bearer-2"},
        ],
    }

    migrated, changed_fields = migrate_tenant_settings_payload(settings, fernet)

    assert "jira.api_token" in changed_fields
    assert "jira.bearer" in changed_fields
    assert "jira_integrations[0].apiToken" in changed_fields
    assert "jira_integrations[0].bearerToken" in changed_fields
    assert migrated["jira"]["api_token"].startswith("enc:")
    assert migrated["jira"]["bearer"].startswith("enc:")
    assert migrated["jira_integrations"][0]["apiToken"].startswith("enc:")
    assert migrated["jira_integrations"][0]["bearerToken"].startswith("enc:")


def test_keeps_already_encrypted_values_unchanged():
    fernet = Fernet(Fernet.generate_key())
    existing = "enc:already-encrypted"
    settings = {
        "jira": {"api_token": existing},
        "jira_integrations": [{"apiToken": existing}],
    }

    migrated, changed_fields = migrate_tenant_settings_payload(settings, fernet)

    assert changed_fields == []
    assert migrated == settings


def test_ignores_non_dict_settings_payload():
    fernet = Fernet(Fernet.generate_key())
    payload = ["unexpected", "shape"]

    migrated, changed_fields = migrate_tenant_settings_payload(payload, fernet)

    assert migrated == payload
    assert changed_fields == []
