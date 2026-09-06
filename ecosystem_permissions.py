import os

from app import db, hash_token, now

PERMISSIONS = {
    'ung.admin': 'Cross-platform UNG administrator override',
    'nexus.endpoints.read': 'Read NEXUS endpoint registry',
    'nexus.endpoints.write': 'Manage NEXUS endpoint registry',
    'nexus.messages.read': 'Read NEXUS integration messages',
    'nexus.messages.write': 'Route NEXUS integration messages',
    'apollo.plans.read': 'Read APOLLO plans',
    'apollo.plans.write': 'Manage APOLLO plans',
    'apollo.assessments.read': 'Read APOLLO assessments',
    'apollo.assessments.write': 'Manage APOLLO assessments',
    'aegis.policies.read': 'Read AEGIS protection policies',
    'aegis.policies.write': 'Manage AEGIS protection policies',
    'aegis.evaluate': 'Evaluate AEGIS protection policy decisions',
    'vector.locations.read': 'Read VECTOR locations',
    'vector.locations.write': 'Manage VECTOR locations',
    'vector.inventory.read': 'Read VECTOR inventory',
    'vector.inventory.write': 'Manage VECTOR inventory',
    'vector.movements.read': 'Read VECTOR movements',
    'vector.movements.write': 'Create VECTOR movements',
}

NEXUS_SERVICE_TOKEN = os.environ.get('UNG_NEXUS_SERVICE_TOKEN', '').strip()


def seed_ecosystem_permissions():
    c = db()
    try:
        for name, description in PERMISSIONS.items():
            c.execute('INSERT OR IGNORE INTO permissions(name,description) VALUES(?,?)', (name, description))

        admin = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
        if admin:
            for name in PERMISSIONS:
                c.execute('INSERT OR IGNORE INTO role_permissions(role_id,permission_name) VALUES(?,?)', (admin['id'], name))

        # Dedicated machine identity for UNG-NEXUS. The raw credential lives only in
        # Railway environment variables; IAM stores only its SHA-256 hash.
        role = c.execute("SELECT id FROM roles WHERE name='nexus-service'").fetchone()
        role_id = role['id'] if role else 'role-nexus-service'
        if not role:
            c.execute(
                'INSERT INTO roles(id,name,description,created_at) VALUES(?,?,?,?)',
                (role_id, 'nexus-service', 'UNG-NEXUS integration service identity', now()),
            )
        for permission in ('platform:service', 'nexus.endpoints.read', 'nexus.endpoints.write', 'nexus.messages.read', 'nexus.messages.write'):
            c.execute('INSERT OR IGNORE INTO role_permissions(role_id,permission_name) VALUES(?,?)', (role_id, permission))

        identity = c.execute("SELECT id FROM identities WHERE id='svc-ung-nexus'").fetchone()
        if not identity:
            c.execute(
                'INSERT INTO identities(id,identity_type,access_class,display_name,email,password_hash,is_active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)',
                ('svc-ung-nexus', 'service', 'service', 'UNG-NEXUS', None, None, now(), now()),
            )
        c.execute('INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)', ('svc-ung-nexus', role_id))

        if NEXUS_SERVICE_TOKEN:
            credential_hash = hash_token(NEXUS_SERVICE_TOKEN)
            c.execute(
                'INSERT OR IGNORE INTO service_credentials(credential_hash,identity_id,label,expires_at,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)',
                (credential_hash, 'svc-ung-nexus', 'UNG-NEXUS production integration', None, now()),
            )
        c.commit()
    finally:
        c.close()
