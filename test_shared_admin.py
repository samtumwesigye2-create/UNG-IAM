import os,tempfile,unittest
from unittest.mock import patch
from fastapi import HTTPException

class SharedAdminTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        os.environ['UNG_IAM_DB']=cls.temp.name+'/iam.db'
        os.environ['UNG_IAM_DATABASE_URL']=''
        os.environ['UNG_IAM_BOOTSTRAP_EMAIL']=''
        os.environ['UNG_IAM_BOOTSTRAP_PASSWORD']=''
        import app
        cls.app=app

    def setUp(self):
        self.env=patch.dict(os.environ,{'UNG_IAM_SHARED_ADMIN_EMAIL':'owner@example.com','UNG_IAM_SHARED_AUTH_URL':'https://authority.example'})
        self.env.start();self.addCleanup(self.env.stop)
        c=self.app.db();c.execute('DELETE FROM sessions');c.execute('DELETE FROM identity_roles');c.execute('DELETE FROM identities');c.commit();c.close()

    def test_verified_master_issues_normal_janus_session(self):
        with patch('shared_admin.verify_master',return_value=True):
            result=self.app.login(self.app.LoginRequest(email='owner@example.com',password='example-master'))
        self.assertTrue(result['access_token'].startswith('iam_'))
        self.assertIn('platform-admin',result['identity']['roles'])
        self.assertIsNotNone(self.app.resolve_principal(result['access_token']))

    def test_wrong_master_cannot_use_old_password(self):
        c=self.app.db();c.execute('INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)',('id','human','corporate','Owner','owner@example.com',self.app.password_hash('old-password'),self.app.now(),self.app.now()));c.commit();c.close()
        with patch('shared_admin.verify_master',side_effect=HTTPException(401,'Invalid credentials')):
            with self.assertRaises(HTTPException) as raised:
                self.app.login(self.app.LoginRequest(email='owner@example.com',password='old-password'))
        self.assertEqual(raised.exception.status_code,401)
        c=self.app.db();self.assertEqual(c.execute('SELECT count(*) n FROM sessions').fetchone()['n'],0);c.close()

    def test_disabled_identity_is_not_reenabled(self):
        c=self.app.db();c.execute('INSERT INTO identities VALUES(?,?,?,?,?,?,0,?,?)',('id','human','corporate','Owner','owner@example.com',None,self.app.now(),self.app.now()));c.commit();c.close()
        with patch('shared_admin.verify_master',return_value=True):
            with self.assertRaises(HTTPException):
                self.app.login(self.app.LoginRequest(email='owner@example.com',password='example-master'))

    def test_other_accounts_remain_local(self):
        with patch('shared_admin.verify_master',side_effect=AssertionError('Wrong authority')):
            with self.assertRaises(HTTPException):
                self.app.login(self.app.LoginRequest(email='staff@example.com',password='example-master'))
