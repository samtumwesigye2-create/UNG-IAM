from app import db, now

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


def seed_ecosystem_permissions():
    c = db()
    try:
        for name, description in PERMISSIONS.items():
            c.execute('INSERT OR IGNORE INTO permissions(name,description) VALUES(?,?)', (name, description))
        admin = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
        if admin:
            for name in PERMISSIONS:
                c.execute('INSERT OR IGNORE INTO role_permissions(role_id,permission_name) VALUES(?,?)', (admin['id'], name))
        c.commit()
    finally:
        c.close()
