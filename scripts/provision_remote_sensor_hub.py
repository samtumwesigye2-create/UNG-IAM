"""Idempotently provision the Remote Sensor Hub service identity."""
from __future__ import annotations

import time
import uuid

from db import connect

DISPLAY_NAME = "Remote Sensor Hub"
CREDENTIAL_HASH = "f33984926a838151f47dc611f7fd863dc6f07f5d1165fe401c4067c0e5b665d5"
LABEL = "Macaly Remote Sensor Hub"


def main() -> None:
    c = connect()
    try:
        role = c.execute("SELECT id FROM roles WHERE name='service'").fetchone()
        if not role:
            raise RuntimeError("service role is missing")

        row = c.execute(
            "SELECT id FROM identities WHERE display_name=? AND identity_type='service' ORDER BY created_at ASC",
            (DISPLAY_NAME,),
        ).fetchone()
        ts = time.time()
        if row:
            iid = row["id"]
            c.execute(
                "UPDATE identities SET access_class='service', is_active=1, updated_at=? WHERE id=?",
                (ts, iid),
            )
        else:
            iid = str(uuid.uuid4())
            c.execute(
                "INSERT INTO identities(id,identity_type,access_class,display_name,email,password_hash,is_active,created_at,updated_at) "
                "VALUES(?,?,?,?,NULL,NULL,1,?,?)",
                (iid, "service", "service", DISPLAY_NAME, ts, ts),
            )

        c.execute(
            "INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)",
            (iid, role["id"]),
        )
        exists = c.execute(
            "SELECT credential_hash FROM service_credentials WHERE credential_hash=?",
            (CREDENTIAL_HASH,),
        ).fetchone()
        if not exists:
            c.execute(
                "INSERT INTO service_credentials(credential_hash,identity_id,label,expires_at,created_at,last_used_at) "
                "VALUES(?,?,?,NULL,?,NULL)",
                (CREDENTIAL_HASH, iid, LABEL, ts),
            )
        c.commit()
        print("Remote Sensor Hub service identity provisioned")
    finally:
        c.close()


if __name__ == "__main__":
    main()
