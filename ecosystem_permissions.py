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
    'apollo.intelligence.read': 'Read APOLLO intelligence',
    'apollo.intelligence.write': 'Ingest APOLLO intelligence',
    'apollo.scenarios.read': 'Read APOLLO scenarios',
    'apollo.scenarios.write': 'Manage APOLLO scenarios',
    'apollo.recommendations.read': 'Read APOLLO recommendations',
    'apollo.recommendations.write': 'Manage APOLLO recommendations',
    'apollo.briefs.read': 'Read APOLLO decision briefs',
    'aegis.policies.read': 'Read AEGIS protection policies',
    'aegis.policies.write': 'Manage AEGIS protection policies',
    'aegis.evaluate': 'Evaluate AEGIS protection policy decisions',
    'vector.locations.read': 'Read VECTOR locations',
    'vector.locations.write': 'Manage VECTOR locations',
    'vector.inventory.read': 'Read VECTOR inventory',
    'vector.inventory.write': 'Manage VECTOR inventory',
    'vector.movements.read': 'Read VECTOR movements',
    'vector.movements.write': 'Create VECTOR movements',
    'procure.requests.read': 'Read procurement requests',
    'procure.requests.write': 'Manage procurement requests',
    'procure.vendors.read': 'Read procurement vendors',
    'procure.vendors.write': 'Manage procurement vendors',
    'procure.bids.read': 'Read procurement bids',
    'procure.bids.write': 'Manage procurement bids',
    'procure.awards.write': 'Award procurement bids',
    'procure.orders.read': 'Read procurement purchase orders',
}

NEXUS_SERVICE_TOKEN = os.environ.get('UNG_NEXUS_SERVICE_TOKEN', '').strip()
PROCURE_SERVICE_TOKEN = os.environ.get('UNG_PROCURE_SERVICE_TOKEN', '').strip()


def _ensure_service_identity(c, *, role_name, role_id, identity_id, display_name, permissions, token, label):
    role = c.execute('SELECT id FROM roles WHERE name=?', (role_name,)).fetchone()
    actual_role_id = role['id'] if role else role_id
    if not role:
        c.execute(
            'INSERT INTO roles(id,name,description,created_at) VALUES(?,?,?,?)',
            (actual_role_id, role_name, f'{display_name} service identity', now()),
        )
    for permission in permissions:
        c.execute('INSERT OR IGNORE INTO role_permissions(role_id,permission_name) VALUES(?,?)', (actual_role_id, permission))

    identity = c.execute('SELECT id FROM identities WHERE id=?', (identity_id,)).fetchone()
    if not identity:
        c.execute(
            'INSERT INTO identities(id,identity_type,access_class,display_name,email,password_hash,is_active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)',
            (identity_id, 'service', 'service', display_name, None, None, now(), now()),
        )
    c.execute('INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)', (identity_id, actual_role_id))

    if token:
        credential_hash = hash_token(token)
        c.execute(
            'INSERT OR IGNORE INTO service_credentials(credential_hash,identity_id,label,expires_at,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)',
            (credential_hash, identity_id, label, None, now()),
        )


def seed_ecosystem_permissions():
    c = db()
    try:
        for name, description in PERMISSIONS.items():
            c.execute('INSERT OR IGNORE INTO permissions(name,description) VALUES(?,?)', (name, description))

        admin = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
        if admin:
            for name in PERMISSIONS:
                c.execute('INSERT OR IGNORE INTO role_permissions(role_id,permission_name) VALUES(?,?)', (admin['id'], name))

        _ensure_service_identity(
            c,
            role_name='nexus-service',
            role_id='role-nexus-service',
            identity_id='svc-ung-nexus',
            display_name='UNG-NEXUS',
            permissions=('platform:service', 'nexus.endpoints.read', 'nexus.endpoints.write', 'nexus.messages.read', 'nexus.messages.write'),
            token=NEXUS_SERVICE_TOKEN,
            label='UNG-NEXUS production integration',
        )

        _ensure_service_identity(
            c,
            role_name='procure-service',
            role_id='role-procure-service',
            identity_id='svc-ung-procure',
            display_name='UNG-PROCURE',
            permissions=('nexus.messages.write', 'procure.requests.read', 'procure.orders.read'),
            token=PROCURE_SERVICE_TOKEN,
            label='UNG-PROCURE production integration',
        )

        c.commit()
    finally:
        c.close()
