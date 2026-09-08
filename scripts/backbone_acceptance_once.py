from __future__ import annotations
import json, os, secrets, urllib.error, urllib.request, uuid
from app import db, hash_token, now


def _call(url: str, method: str='GET', payload: dict|None=None, token: str=''):
    data=None; headers={'Accept':'application/json','User-Agent':'UNG-IAM-Backbone-Acceptance/1.0'}
    if payload is not None:
        data=json.dumps(payload,separators=(',',':')).encode(); headers['Content-Type']='application/json'
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(url,data=data,method=method,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            raw=r.read().decode(); return int(r.status),json.loads(raw or '{}')
    except urllib.error.HTTPError as e:
        try: body=json.loads(e.read().decode() or '{}')
        except Exception: body={}
        return int(e.code),body


def main():
    if os.getenv('UNG_BACKBONE_ACCEPTANCE_ONCE','0')!='1': return
    nexus=os.getenv('NEXUS_BASE_URL','https://ung-nexus-production.up.railway.app').rstrip('/')
    pulsar=os.getenv('PULSAR_BASE_URL','https://ung-pulsar-production.up.railway.app').rstrip('/')
    iid=str(uuid.uuid4()); rid=str(uuid.uuid4()); raw='svc_'+secrets.token_urlsafe(48); mid1=str(uuid.uuid4()); mid2=str(uuid.uuid4())
    result={'nexus_health':False,'pulsar_health':False,'nexus_relay':False,'pulsar_persisted':False,'nexus_duplicate':False,'pulsar_duplicate':False,'unauth_rejected':False,'cleanup':False,'message_ids':[mid1,mid2]}
    c=db()
    try:
        c.execute("INSERT OR IGNORE INTO permissions(name,description) VALUES(?,?)",('nexus.messages.write','Route NEXUS messages'))
        c.execute('INSERT INTO roles(id,name,description,created_at) VALUES(?,?,?,?)',(rid,'backbone-acceptance-'+rid[:8],'Temporary NEXUS PULSAR acceptance role',now()))
        c.execute('INSERT INTO role_permissions(role_id,permission_name) VALUES(?,?)',(rid,'nexus.messages.write'))
        c.execute('INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)',(iid,'service','service','Temporary Backbone Acceptance',None,None,now(),now()))
        c.execute('INSERT INTO identity_roles(identity_id,role_id) VALUES(?,?)',(iid,rid))
        c.execute('INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)',(hash_token(raw),iid,'temporary-backbone-acceptance',now()+900,now())); c.commit()
        result['nexus_health']=_call(nexus+'/health')[0]==200
        result['pulsar_health']=_call(pulsar+'/health')[0]==200
        env1={'message_id':mid1,'source_system':'UNG-IAM-ACCEPTANCE','target_system':'UNG-VECTOR','message_type':'BACKBONE.ACCEPTANCE','payload':{'synthetic':True,'acceptance':True}}
        s1,b1=_call(nexus+'/v1/messages','POST',env1,raw); result['nexus_relay']=s1==202 and b1.get('status')=='relayed'
        s2,b2=_call(pulsar+'/v1/nexus/status/'+mid1,'GET',None,raw); result['pulsar_persisted']=s2==200 and b2.get('found') is True
        s3,b3=_call(nexus+'/v1/messages','POST',env1,raw); result['nexus_duplicate']=s3==202 and b3.get('duplicate') is True
        env2={'message_id':mid2,'source_system':'UNG-IAM-ACCEPTANCE','target_system':'UNG-VECTOR','message_type':'BACKBONE.DEDUPE.ACCEPTANCE','payload':{'synthetic':True,'acceptance':True}}
        s4,b4=_call(pulsar+'/v1/nexus/inbound','POST',env2,raw); s5,b5=_call(pulsar+'/v1/nexus/inbound','POST',env2,raw)
        result['pulsar_duplicate']=s4==202 and b4.get('duplicate') is False and s5==202 and b5.get('duplicate') is True
        s6,_=_call(nexus+'/v1/messages','POST',{'message_id':str(uuid.uuid4()),'source_system':'UNG-IAM-ACCEPTANCE','target_system':'UNG-VECTOR','message_type':'BACKBONE.UNAUTH','payload':{'synthetic':True}}); result['unauth_rejected']=s6==401
    except Exception as exc:
        result['error']=type(exc).__name__
    finally:
        try:
            c.execute('DELETE FROM service_credentials WHERE identity_id=?',(iid,)); c.execute('DELETE FROM identity_roles WHERE identity_id=?',(iid,)); c.execute('DELETE FROM identities WHERE id=?',(iid,)); c.execute('DELETE FROM role_permissions WHERE role_id=?',(rid,)); c.execute('DELETE FROM roles WHERE id=?',(rid,)); c.commit(); result['cleanup']=True
        except Exception as exc: result['cleanup_error']=type(exc).__name__
        c.close()
    result['passed']=all(result[k] for k in ['nexus_health','pulsar_health','nexus_relay','pulsar_persisted','nexus_duplicate','pulsar_duplicate','unauth_rejected','cleanup'])
    print('BACKBONE_ACCEPTANCE_RESULT='+json.dumps(result,separators=(',',':')),flush=True)
