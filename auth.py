from google.appengine.api import users
from google.appengine.ext import db

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

import time
import zlib
import base64
import pickle
import os.path
import webapp2

RNG = Random.new().read

with open(os.path.join(os.path.dirname(__file__), 'keypair/PRIVATE_KEY'), 'r') as f:
  PRIVATE_KEY = RSA.importKey(f.read())

with open(os.path.join(os.path.dirname(__file__), 'keypair/REMOTE_KEY'), 'r') as f:
  REMOTE_KEY = RSA.importKey(f.read())

class AuthRequest(db.Model):
    request_data = db.BlobProperty()

class AuthPage(webapp2.RequestHandler):
    def get(self):
        request_data = None
        
        key = self.request.get('key')
        
        if not key:
            b64_req = self.request.get('req')
            b64_sig = self.request.get('sig')
            
            if not b64_req or not b64_sig:
                return self.error(400)
            
            gzp_req = base64.urlsafe_b64decode(b64_req.encode('ascii'))
            gzp_sig = base64.urlsafe_b64decode(b64_sig.encode('ascii'))
            
            if not gzp_req or not gzp_sig:
                return self.error(400)
            
            pkl_req = zlib.decompress(gzp_req)
            pkl_sig = zlib.decompress(gzp_sig)
            
            if not pkl_req or not pkl_sig:
                return self.error(400)
            
            enc_req = pickle.loads(pkl_req)
            enc_sig = pickle.loads(pkl_sig)
            
            if not enc_req or not enc_sig:
                return self.error(400)
            
            req = PRIVATE_KEY.decrypt(enc_req)
            sig = SHA256.new(req).digest()
            
            if not REMOTE_KEY.verify(sig, enc_sig):
                return self.error(401)
            
            if req is None:
                return self.error(400)
                
            request_data = pickle.loads(req)
                
            if not 'time' in request_data:
                return self.error(400)
                
            if time.time() > request_data['time'] + 15:
                return self.error(408)
                
            if not 'location' in request_data:
                return self.error(400)
        
        user = users.get_current_user()
        
        if user is None:
            auth_request = AuthRequest()
            auth_request.request_data = req
            auth_request.put()
            
            key = auth_request.key().id()
        
            return self.redirect(users.create_login_url('/auth/?key=%s' % key))
             
        if not key is None and request_data is None:
            try:
                auth_request = AuthRequest.get_by_id(int(key))
                
            except:
                return self.error(404)
                
            if auth_request is None:
                return self.error(404)
            
            request_data = pickle.loads(auth_request.request_data)
            auth_request.delete()
        
        response_data = {}
        response_data['time'] = time.time()
        response_data['email'] = user.email()
        response_data['user_id'] = user.user_id()
        response_data['nickname'] = user.nickname()
        response_data['is_admin'] = users.is_current_user_admin()
        
        rsp = pickle.dumps(response_data)
        sig = SHA256.new(rsp).digest()
        
        enc_rsp = REMOTE_KEY.encrypt(rsp, RNG)
        enc_sig = PRIVATE_KEY.sign(sig, RNG)
        
        pkl_rsp = pickle.dumps(enc_rsp)
        pkl_sig = pickle.dumps(enc_sig)
        
        gzp_rsp = zlib.compress(pkl_rsp, 9)
        gzp_sig = zlib.compress(pkl_sig, 9)
        
        b64_rsp = base64.urlsafe_b64encode(gzp_rsp)
        b64_sig = base64.urlsafe_b64encode(gzp_sig)
        
        self.redirect(request_data['location'] % {'rsp': b64_rsp, 'sig': b64_sig})

app = webapp2.WSGIApplication([('/auth/', AuthPage)])
