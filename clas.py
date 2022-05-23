import base64, math, time, json, uuid, binascii, config
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA

deserialmap = {}

class UUIDNoSign():
    def __init__(self, uuid):
        self.uuid = uuid.replace("-", "").lower()
        if len(self.uuid) != 32:
            raise ValueError("Not a valid uuid")
        for x in self.uuid:
            if x not in "1234567890abcdef":
                raise ValueError("Not a valid uuid")
    def value(self):
        return self.uuid
    def bytes(self):
        return binascii.unhexlify(self.uuid)
    def signed(self):
        return self.uuid[0:8]+"-"+self.uuid[8:12]+"-"+self.uuid[12:16]+"-"+self.uuid[16:20]+"-"+self.uuid[20:32]

def genUUIDByName(name):
    class n:
        bytes = b''
    return UUIDNoSign(uuid.uuid3(n, "OfflinePlayer:"+name).hex)

def genUUID():
    return UUIDNoSign(uuid.uuid4().hex)

def Data_sign(data):
    if hasattr(data, "encode"):
        data = data.encode('utf-8')
    private_key = RSA.importKey(open(config.private_key, "rb").read())
    cipher = PKCS1_v1_5.new(private_key)
    h = SHA.new(data)
    sign = cipher.sign(h)
    return base64.b64encode(sign).decode()

def get_pub():
    privKey = RSA.importKey(open(config.private_key, "rb").read())
    pubKey = privKey.publickey()
    export_byte = pubKey.export_key("PEM")
    return export_byte.decode()

class Player():
    def __init__(self, uid):
        self.id = uid
        self.properties = []
        self.self = self
    def addProperty(self, obj):
        self.properties.append(obj)
    def removeProperty(self, name):
        for x in range(0, len(self.properties)):
            if type(x) == dict:
                if self.properties[x].get("name") == name:
                    del self.properties[x]
                    break
            else:
                if invmap[type(x)] == name:
                    del self.properties[x]
                    break
    def getProperty(self, name):
        for x in self.properties:
            if x["name"] == name:
                return x["value"]
        return None
    def serialize(self, sign=False):
        rtd = dict()
        rtd['id'] = self.id.value()
        if len(self.properties) > 0:
            rtd['properties'] = []
            for x in self.properties:
                if hasattr(x, "serialize"):
                    rtd["properties"].append(x.serialize(sign=sign))
                else:
                    if sign:
                        xnew = x.copy()
                        xnew['signature'] = Data_sign(x['value'])
                        rtd["properties"].append(xnew)
                    else:
                        rtd["properties"].append(x)
        return rtd
    def deserialize(itm, itm2=None):
        if itm2 != None:
            itm = itm2
        if type(itm) != dict:
            itm = json.loads(itm)
        py = Player(UUIDNoSign(itm['id']))
        if 'properties' in itm.keys():
            py.properties = []
            for x in itm['properties']:
                if x['name'] in deserialmap.keys():
                    py.properties.append(deserialmap[x['name']].deserialize(x['value']))
                else:
                    py.properties.append(x)
        return py

class Profile():
    def __init__(self, uid, name):
        self.id = uid
        self.name = name
        self.properties = []
        self.self = self
        self.propertyName = "profile"
    def addProperty(self, obj):
        self.properties.append(obj)
    def removeProperty(self, name):
        for x in range(0, len(self.properties)):
            if type(x) == dict:
                if self.properties[x].get("name") == name:
                    del self.properties[x]
                    break
            else:
                if invmap[type(x)] == name:
                    del self.properties[x]
                    break
    def getProperty(self, name):
        for x in self.properties:
            if type(x) != dict:
                if deserialmap.get(name) == type(x):
                    return x
            else:
                if x["name"] == name:
                    return x["value"]
        return None
    def serialize(self, sign=False):
        rtd = dict()
        rtd['id'] = self.id.value()
        rtd['name'] = self.name
        if len(self.properties) > 0:
            rtd['properties'] = []
            for x in self.properties:
                if hasattr(x, "serialize"):
                    rtd["properties"].append(x.serialize(sign=sign))
                else:
                    if sign:
                        xnew = x.copy()
                        xnew['signature'] = Data_sign(x['value'])
                        rtd["properties"].append(xnew)
                    else:
                        rtd["properties"].append(x)
        print(rtd)
        return rtd
    def deserialize(itm, itm2=None):
        if itm2 != None:
            itm = itm2
        if type(itm) != dict:
            itm = json.loads(itm)
        py = Profile(UUIDNoSign(itm['id']), itm['name'])
        if 'properties' in itm.keys():
            py.properties = []
            for x in itm['properties']:
                if x['name'] in deserialmap.keys():
                    py.properties.append(deserialmap[x['name']].deserialize(x['value']))
                else:
                    py.properties.append(x)
        return py

class Texture():
    def __init__(self, uid, name):
        self.timestamp = math.floor(time.time()*1000)
        self.profileId = UUIDNoSign(uid)
        self.profileName = name
        self.textures = dict()
        self.propertyName = "texture"
        self.self = self
    def SkinModify(self, typ, url, metadata=None):
        self.textures[typ.upper()] = dict()
        self.textures[typ.upper()]['url'] = url
        if metadata != None:
            self.textures[typ.upper()]['metadata'] = metadata
    def deleteSkin(self, typ):
        if self.textures.get(typ.upper()) != None:
            del self.textures[typ.upper()]
    def serialize(self, sign=False):
        ud = dict()
        ud['timestamp'] = self.timestamp
        ud['profileId'] = self.profileId.value()
        ud['profileName'] = self.profileName
        ud['textures'] = self.textures
        st = json.dumps(ud)
        rtv = {"name":"textures", "value":base64.b64encode(st.encode()).decode()}
        if sign:
            rtv['signature'] = Data_sign(rtv['value'])
        return rtv
    def deserialize(itm, itm2=None):
        if itm2 != None:
            itm = itm2
        itm = json.loads(base64.b64decode(itm.encode()).decode())
        ty = Texture(itm['profileId'],itm['profileName'])
        ty.timestamp = itm['timestamp']
        ty.textures = itm['textures']
        return ty
        
deserialmap["textures"] = Texture
invmap = {v:k for k,v in deserialmap.items()}
