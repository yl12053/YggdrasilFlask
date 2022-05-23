import flask
from sqlalchemy.orm.attributes import flag_modified
import error, clas, upload, config
from flask import request, abort, Response
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import sqlalchemy
import binascii, hashlib, json, os, inspect, traceback, io, math, time
from PIL import Image, UnidentifiedImageError
from datetime import datetime
import threading
import werkzeug.exceptions
from flask_limiter import Limiter
import bcrypt
from sqlalchemy.dialects import mysql

os.chdir(os.path.dirname(os.path.realpath(__file__)))

app = flask.Flask(__name__)
def func_limit():
    return str(request.json.get("username"))

limiter = Limiter(app, key_func=func_limit)

desc = sqlalchemy.desc
asc = sqlalchemy.asc

Image.MAX_IMAGE_PIXELS = config.maximum_pixel

#Database
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = config.use
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_BINDS'] = config.binds
db.init_app(app)

class PlayerLogin(db.Model):
    __tablename__ = "Player_Login"
    id = db.Column(db.BINARY(16), unique=True, nullable=False, primary_key=True)
    email = db.Column(db.VARCHAR(255))
    password = db.Column(db.BINARY(32), nullable=False)
    external_qq = db.Column(db.VARCHAR(255))
    def __init__(self, id, password, email=None, external_qq=None):
        self.id = id
        self.password = password
        self.email = email
        self.external_qq = external_qq
        
class PlayerData(db.Model):
    __tablename__ = "Player_Data"
    id = db.Column(db.BINARY(16), unique=True, nullable=False, primary_key=True)
    serialized_data = db.Column(db.TEXT, nullable=False)
    character = db.Column(db.JSON)
    def __init__(self, id, serialized_data, character):
        self.id = id
        self.serialized_data = serialized_data
        self.character = self.character
        
class ProfileData(db.Model):
    __tablename__ = "Profile_Data"
    id = db.Column(db.BINARY(16), unique=True, nullable=False, primary_key=True)
    serialized_data = db.Column(db.TEXT, nullable=False)
    name = db.Column(db.VARCHAR(255), nullable=False)
    player_belong = db.Column(db.BINARY(16), nullable=False)
    def __init__(self, id, serialized_data, name, player_belong):
        self.id = id
        self.serialized_data = serialized_data
        self.name = name
        self.player_belong = player_belong
        
class Token(db.Model):
    __tablename__ = "Token"
    accessToken = db.Column(db.BINARY(16), unique=True, nullable=False, primary_key=True)
    clientToken = db.Column(db.TEXT, nullable=False)
    validity = db.Column(db.Integer, nullable=False)
    profile = db.Column(db.BINARY(16))
    timestamp = db.Column(db.DateTime)
    player = db.Column(db.BINARY(16), nullable=False)
    def __init__(self, accessToken, clientToken, validity, profile, timestamp, player):
        self.accessToken = accessToken
        self.clientToken = clientToken
        self.validity = validity
        self.profile = profile
        self.timestamp = timestamp
        self.player = player
        
        
class C_S_Record(db.Model):
    __tablename__ = "Client_Bind"
    accessToken = db.Column(db.BINARY(16), unique=True, nullable=False, primary_key=True)
    useProfile = db.Column(db.BINARY(16), nullable=False)
    serverId = db.Column(db.VARCHAR(764), nullable=False, primary_key=True)
    timestamp = db.Column(db.DateTime(), nullable=False)
    ip = db.Column(db.VARCHAR(255), nullable=False)
    username = db.Column(db.VARCHAR(255), nullable=False)
    def __init__(self, accessToken, useProfile, serverId, timestamp, ip, username):
        self.accessToken = accessToken
        self.useProfile = useProfile
        self.timestamp = timestamp
        self.serverId = serverId
        self.ip = ip
        self.username = username

class ForumUser(db.Model):
    __bind_key__ = 'forum'
    __tablename__ = 'users'
    id = db.Column(db.INT(), primary_key=True, nullable=False)
    username = db.Column(db.VARCHAR(100), nullable=False)
    nickname = db.Column(db.VARCHAR(255))
    email = db.Column(db.VARCHAR(150), nullable=False)
    is_email_confirmed = db.Column(mysql.TINYINT(1), nullable=False)
    password = db.Column(db.VARCHAR(100), nullable=False)
    avatar_url = db.Column(db.VARCHAR(100))
    preferences = db.Column(db.BLOB)
    joined_at = db.Column(db.DateTime)
    last_seen_at = db.Column(db.DateTime)
    marked_all_as_read_at = db.Column(db.DateTime)
    read_notifications_at = db.Column(db.DateTime)
    discussion_count = db.Column(db.INT(), nullable=False)
    comment_count = db.Column(db.INT(), nullable=False)
    read_flags_at = db.Column(db.DateTime)
    suspended_until = db.Column(db.DateTime)
    suspend_reason = db.Column(db.Text)
    bio = db.Column(db.Text)
    blocks_byobu_pd = db.Column(mysql.TINYINT(1), nullable=False)
    def __init__(self, id, username, nickname, email, is_email_confirmed, password, avatar_url, preferences, joined_at, last_seen_at, marked_all_as_read_at, read_notifications_at, discussion_count, comment_count, read_flags_at, suspended_until, suspended_reason, bio, blocks_byobu_pd):
        self.id = id
        self.username = username
        self.nickname = nickname
        self.email = email
        self.is_email_confirmed = is_email_confirmed
        self.password = password
        self.avatar_url = avatar_url
        self.preferences = preferences
        self.joined_at = joined_at
        self.last_seen_at = last_seen_at
        self.marked_all_as_read_at = marked_all_as_read_at
        self.read_notifications_at = read_notifications_at
        self.discussion_count = discussion_count
        self.comment_count = comment_count
        self.read_flags_at = read_flags_at
        self.suspended_until = suspended_until
        self.suspended_reason = suspended_reason
        self.bio = bio
        self.blocks_byobu_pd = blocks_byobu_pd

class ForumBind(db.Model):
    __tablename__ = "Forum_Bind"
    id = db.Column(db.BINARY(16), primary_key=True)
    forum_id = db.Column(db.INT, nullable=False)
    forum_username = db.Column(db.VARCHAR(255), nullable=False)
    def __init__(self, id, forum_id, forum_username):
        self.id = id
        self.forum_id = forum_id
        self.forum_username = forum_username

#Cleaner
def Token_Cleaner(app):
    with app.app_context():
        while True:
            try:
                fetched = Token.query.filter_by(validity=3).count()
                if fetched > config.maximum_amount_query_allowed:
                    for x in range(fetched-config.maximum_amount_query_allowed):
                        db.session.delete(Token.query.filter_by(validity=3).order_by(asc(Token.timestamp)).first())
                        db.session.commit()
                dt = datetime.fromtimestamp(time.time()-3600)
                n = C_S_Record.query.filter(C_S_Record.timestamp < dt).first()
                while n != None:
                    db.session.delete(n)
                    db.session.commit()
                    n = C_S_Record.query.filter(C_S_Record.timestamp < dt).first()
            except:
                pass

thread_token = threading.Thread(target=Token_Cleaner, args=(app,))
thread_token.daemon = True
thread_token.start()

#ALI Injector
@app.after_request
def after_request(response):
    response.headers["X-Authlib-Injector-API-Location"] = "/"
    return response

#Error Handler
#response.headers['Content-Type'] = 'application/json; charset=utf-8'

@app.errorhandler(429)
def limit_exp(resp):
    err = error.HTTPError(403)
    err.error = "ForbiddenOperationException"
    return ErrorHandler(err)

@app.errorhandler(Exception)
def handler(err):
    if werkzeug.exceptions.HTTPException in inspect.getmro(type(err)):
        r = flask.Response(json.dumps(error.HTTPError(err.code).serialize()), err.code)
    else:
        print(traceback.format_exc())
        tb = err.__traceback__
        while tb.tb_next is not None:
            tb = tb.tb_next
        r = flask.Response(json.dumps(error.HTTPError(500, os.path.basename(tb.tb_frame.f_code.co_filename)+":"+"Line "+str(tb.tb_lineno)+":"+type(err).__name__+":"+str(err)).serialize()), 500)
    r.headers['Content-Type'] = 'application/json; charset=utf-8;'
    return r

def ErrorHandler(error):
    r = flask.Response(json.dumps(error.serialize()), error.code)
    r.headers['Content-Type'] = 'application/json; charset=utf-8;'
    return r

#Token Handler
def checkToken(accessToken, clientToken=None):
    try:
        accessToken = clas.UUIDNoSign(accessToken).value()
    except ValueError:
        return ErrorHandler(error.InvalidToken())
    if clientToken == None:
        token = Token.query.filter_by(accessToken=binascii.unhexlify(accessToken)).first()
    else:
        token = Token.query.filter_by(accessToken=binascii.unhexlify(accessToken), clientToken=str(clientToken)).first()
    if token == None:
        return None
    if (datetime.now() - token.timestamp).total_seconds() >= config.timeout_temp:
        if (datetime.now() - token.timestamp).total_seconds() >= config.timeout_revoke:
            token.validity = 3
        else:
            token.validity = 2
        db.session.commit()
    return token

#Authenticate Endpoint
@app.route('/authserver/authenticate', methods = ["POST"])
@limiter.limit('1 per %d second'%(config.rate))
def Authenticate():
    if request.json == None:
        abort(403)
    else:
        for x in ["username", "password", "requestUser", "agent"]:
            if x not in request.json.keys():
                if x in ["username", "password"]:
                    return ErrorHandler(error.InvalidCredentials())
                elif x == "requestUser":
                    request.json["requestUser"] = False
                elif x == "agent":
                    abort(403)
        if request.json['agent'] != {"name":"Minecraft", "version":1}:
            abort(400)
        response = ForumUser.query.filter_by(email=request.json['username'], is_email_confirmed=1).first()
        if response == None:
            r2 = ForumBind.query.filter_by(forum_username=request.json['username']).first()
            if r2 == None:
                return ErrorHandler(error.InvalidCredentials())
            else:
                response = ForumUser.query.filter_by(id=r2.forum_id, username=r2.forum_username)
                if response == None:
                    db.session.delete(r2)
                    db.session.commit()
                    return ErrorHandler(error.InvalidCredentials())
                cused = False
        else:
            r2 = ForumBind.query.filter_by(forum_id=response.id, forum_username=response.username).first()
            if r2 is None:
                return ErrorHandler(error.InvalidCredentials())
            cused=False
        pwd = request.json['password']
        if not bcrypt.checkpw(pwd, response.password):
            return ErrorHandler(error.InvalidCredentials())
        response = PlayerLogin.query.filter_by(id=r2.id)
        toks = Token.query.filter_by(player=response.id, validity=1).all()
        for x in toks:
            x.validity = 2
        db.session.commit()
        avl = PlayerData.query.filter_by(id=response.id).first()
        if avl == None:
            abort(400)
        avlist = [binascii.unhexlify(x) for x in avl.character]
        avaliablepf = []
        print(avlist)
        for x in avlist:
            pfs = ProfileData.query.filter_by(id = x).first()
            if pfs == None:
                return ErrorHandler(error.HTTPError(500, cause="Profile listed not found"))
            dtl = json.loads(pfs.serialized_data)
            if dtl.get("properties") != None:
                del dtl["properties"]
            avaliablepf.append(dtl)
        if cused:
            selectpf = json.loads(r2.serialized_data)
            if selectpf.get("properties") != None:
                del selectpf["properties"]
        else:
            if len(avaliablepf) == 1:
                selectpf = avaliablepf[0]
            else:
                selectpf = None
        if request.json['requestUser']:
            usr = json.loads(avl.serialized_data)
        else:
            usr = None
        accessToken = clas.genUUID()
        while Token.query.filter_by(accessToken = binascii.unhexlify(accessToken.value())).first() != None:
            accessToken = clas.genUUID()
        if request.json.get('clientToken') == None:
            clientToken = clas.genUUID().value()
        else:
            clientToken = request.json['clientToken']
        clientToken = str(clientToken)
        response_json = {}
        if selectpf == None:
            token_object = Token(binascii.unhexlify(accessToken.value()), clientToken, 1, None, datetime.now(), response.id)
        else:
            token_object = Token(binascii.unhexlify(accessToken.value()), clientToken, 1, avlist[0], datetime.now(), response.id)
        db.session.add(token_object)
        db.session.commit()
        response_json['accessToken'] = accessToken.value()
        response_json['clientToken'] = clientToken
        response_json['availableProfiles'] = avaliablepf
        if selectpf != None:
            response_json['selectedProfile'] = selectpf
        if usr != None:
            response_json['user'] = usr
        st = json.dumps(response_json)
        nr = Response(st, 200)
        nr.headers['Content-Type'] = 'application/json; charset=utf-8'
        return nr

@app.route('/authserver/refresh', methods=['POST'])
def RefreshToken():
    if request.json == None:
        abort(403)
    for x in ['accessToken']:
        if x not in request.json.keys():
            if x == "accessToken":
                return ErrorHandler(error.InvalidToken())
    try:
        atk = clas.UUIDNoSign(request.json['accessToken']).value()
    except ValueError:
        return ErrorHandler(error.InvalidToken())
    response = checkToken(atk, request.json.get("clientToken"))
    if response == None or response.validity==3:
        return ErrorHandler(error.InvalidToken())
    if request.json.get('requestUser') != None:
        usr = PlayerData.query.filter_by(id=response.player).first()
        if usr==None:
            return ErrorHandler(error.HTTPError(500, "Player listed but missing data"))
        user = json.loads(usr.serialized_data)
    else:
        user = None
    if request.json.get("selectedProfile") != None:
        if response.profile is not None:
            return ErrorHandler(error.TokenAssigned())
        ud = request.json['selectedProfile']
        pf = clas.Profile.deserialize(ud)
        i = binascii.unhexlify(pf.id.value())
        dat = ProfileData.query.filter_by(id=i).first()
        if dat is None:
            err = error.HTTPError(400)
            err.error = "IllegalArgumentException"
            return ErrorHandler(err)
        if dat.player_belong != response.player:
            return ErrorHandler(error.TokenAssignForbidden())
    else:
        i = response.profile
    response.validity = 3
    db.session.commit()
    nat = clas.genUUID().value()
    while checkToken(nat) != None:
        nat = clas.genUUID().value()
    nt = Token(binascii.unhexlify(nat), response.clientToken, 1, i, datetime.now(), response.player)
    db.session.add(nt)
    db.session.commit()
    rdi = {}
    rdi['accessToken'] = nat
    rdi['clientToken'] = response.clientToken
    if request.json.get("selectedProfile") != None:
        dat = ProfileData.query.filter_by(id=i).first()
        rdi['selectedProfile'] = json.loads(dat.serialized_data)
    else:
        if response.profile != None:
            jssele = ProfileData.query.filter_by(id=response.profile).first()
            rdi['selectedProfile'] = json.loads(jssele.serialized_data)
    if rdi.get("selectedProfile") is not None:
        if rdi['selectedProfile'].get("properties") is not None:
            del rdi['selectedProfile']['properties']
    if user != None:
        rdi['user'] = user
    resp = Response(json.dumps(rdi), 200)
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    return resp
    
@app.route('/authserver/validate', methods=["POST"])
def validate():
    if "accessToken" not in request.json.keys():
        abort(400)
    r = checkToken(request.json['accessToken'], request.json.get('clientToken'))
    if r == None or r.validity == 3:
        return ErrorHandler(error.InvalidToken())
    else:
        return ErrorHandler(error.HTTP204())
        
@app.route('/authserver/invalidate', methods=["POST"])
def revoke():
    if "accessToken" not in request.json.keys():
        abort(400)
    r = checkToken(request.json['accessToken'])
    if r != None:
        r.validity = 3
        db.session.commit()
    return ErrorHandler(error.HTTP204())

@app.route('/authserver/signout', methods=["POST"])
@limiter.limit('1 per %d second'%(config.rate))
def signout():
    for x in ['username', 'password']:
        if x not in request.json.keys():
            abort(400)
    u = ForumUser.query.filter_by(email=request.json['username'], is_email_confirmed=1).first()
    if u == None:
        return ErrorHandler(error.InvalidCredentials())
    fb = ForumBind.query.filter_by(forum_id=u.id, forum_username=u.username).first()
    if fb is None:
        return ErrorHandler(error.InvalidCredentials())
    if not bcrypt.checkpw(request.json['password'], u.password):
        return ErrorHandler(error.InvalidCredentials())
    u = PlayerLogin.query.filter_by(id = fb.id)
    uid = u.id
    tokens = Token.query.filter((Token.player == uid) | (Token.validity != 3)).all()
    for x in tokens:
        x.validity = 3
    db.session.commit()
    return ErrorHandler(error.HTTP204())
    
#Server Client Handshake Endpoint
@app.route('/sessionserver/session/minecraft/join', methods=["POST"])
def client_join():
    for x in ['accessToken', 'selectedProfile', 'serverId']:
        if x not in request.json.keys():
            if x == "accessToken":
                return ErrorHandler(error.InvalidToken())
            err = error.HTTPError(400)
            err.error = "IllegalArgumentException"
            return ErrorHandler(err.error)
    try:
        atk = binascii.unhexlify(clas.UUIDNoSign(request.json['accessToken']).value())
    except ValueError as e:
        return ErrorHandler(error.InvalidToken())
    try:
        sp = binascii.unhexlify(clas.UUIDNoSign(request.json['selectedProfile']).value().encode())
    except ValueError:
        abort(400)
    token_obj = checkToken(binascii.hexlify(atk).decode())
    if token_obj == None:
        return ErrorHandler(error.InvalidToken())
    if token_obj.profile != sp:
        return ErrorHandler(error.InvalidPlayer())
    un = ProfileData.query.filter_by(id=sp).first()
    if un == None:
        abort(400)
    newrecord = C_S_Record(atk, sp, request.json['serverId'], datetime.now(), request.remote_addr, un.name)
    oldrecord = C_S_Record.query.filter_by(accessToken=atk, serverId=request.json['serverId']).first()
    if oldrecord != None:
        db.session.delete(oldrecord)
        db.session.commit()
    db.session.add(newrecord)
    db.session.commit()
    return ErrorHandler(error.HTTP204())
    
@app.route('/sessionserver/session/minecraft/hasJoined', methods=["GET"])
def server_join():
    for x in ['username', 'serverId']:
        if x not in request.args.keys():
            abort(400)
    usr = str(request.args['username'])
    sid = str(request.args['serverId'])
    ip = request.args.get('ip')
    now = datetime.now()
    cbs = C_S_Record.query.filter_by(username=usr, serverId=sid).order_by(desc(C_S_Record.timestamp)).first()
    if cbs == None:
        return ErrorHandler(error.HTTP204())
    if (now-cbs.timestamp).total_seconds() > config.timeout_login:
        db.session.delete(cbs)
        db.session.commit()
        return ErrorHandler(error.HTTP204())
    if ip != None:
        if cbs.ip != ip:
            db.session.delete(cbs)
            db.session.commit()
            return ErrorHandler(error.HTTP204())
    gid = cbs.useProfile
    pf = ProfileData.query.filter_by(id=gid).first()
    rtv = pf.serialized_data
    rto = clas.Profile.deserialize(rtv)
    rtd = json.dumps(rto.serialize(sign=True))
    db.session.delete(cbs)
    db.session.commit()
    respobj = Response(rtd, 200)
    respobj.headers['Content-Type'] = "application/json; charset=utf-8"
    return respobj

#Character information searching endpoint
@app.route("/sessionserver/session/minecraft/profile/<uuid>", methods=["GET"])
def profileGet(uuid):
    if uuid == None:
        abort(400)
    if request.args.get("unsigned") == None:
        unsign = True
    else:
        unsign = request.args.get("unsigned")
        if unsign not in ['true', 'false']:
            abort(400)
        unsign = {"true":True, "false":False}[unsign]
    try:
        u = clas.UUIDNoSign(uuid)
    except ValueError:
        abort(400)
    pd = ProfileData.query.filter_by(id=binascii.unhexlify(u.value())).first()
    if pd == None:
        return ErrorHandler(error.HTTP204())
    if unsign:
        rtd = Response(pd.serialized_data, 200)
        rtd.headers['Content-Type'] = "application/json; charset=utf-8"
        return rtd
    pfc = clas.Profile.deserialize(json.loads(pd.serialized_data))
    rtval = json.dumps(pfc.serialize(sign=True))
    rtd = Response(rtval, 200)
    rtd.headers['Content-Type'] = "application/json; charset=utf-8"
    return rtd

@app.route("/api/profiles/minecraft", methods=["POST"])
def multipleQuery():
    if type(request.json) != list:
        abort(400)
    if len(request.json) > config.maximum_amount_query_allowed:
        abort(403)
    retlist = []
    for x in set(request.json):
        if type(x) != str:
            pass
        pfd = ProfileData.query.filter_by(name=x).first()
        if pfd != None:
            pfc = json.loads(pfd.serialized_data)
            if "properties" in pfc.keys():
                del pfc["properties"]
            retlist.append(pfc)
    req = Response(json.dumps(retlist), 200)
    req.headers["Content-Type"] = "application/json; charset=utf-8"
    return req

#Texture Editing Endpoint
@app.route("/api/user/profile/<uuid>/<textureType>", methods=["PUT", "DELETE"])
def textureEditing(uuid, textureType):
    if request.headers.get("Authorization") == None:
        abort(401)
    auth = request.headers["Authorization"].split()
    if len(auth) != 2:
        abort(401)
    if auth[0] != "Bearer":
        abort(401)
    try:
        accessToken = clas.UUIDNoSign(auth[1]).value()
    except ValueError:
        abort(401)
    atkobj = checkToken(accessToken)
    if atkobj == None:
        abort(401)
    uidc = atkobj.profile
    if uidc != binascii.unhexlify(clas.UUIDNoSign(uuid).value()):
        abort(401)
    if textureType not in ["skin", "cape"]:
        abort(400)
    pfd = ProfileData.query.filter_by(id=uidc).first()
    if pfd == None:
        return ErrorHandler(error.HTTPError(500, "Profile listed but missing data"))
    sd = json.loads(pfd.serialized_data)
    pdata = clas.Profile.deserialize(sd)
    if pdata.getProperty("uploadableTextures") == None:
        pdata.addProperty({"name": "uploadableTextures", "value": "skin,cape"})
    ut = pdata.getProperty("uploadableTextures").split(",")
    if textureType.lower() not in [x.lower() for x in ut]:
        abort(403)
    if pdata.getProperty("textures") == None:
        pdata.addProperty(clas.Texture(pdata.id.value(), pdata.name))
    textureobj = pdata.getProperty("textures")
    if request.method == "PUT":
        if textureType.lower() == "skin":
            if request.form.get("model") == None:
                abort(400)
            elif request.form.get("model") == "":
                model = "default"
            elif request.form.get("model") == "slim":
                model = "slim"
            else:
                abort(400)
        file = request.files.get("file")
        if file == None:
            abort(400)
        filename = file.filename
        mimetype = file.content_type
        if mimetype != "image/png":
            abort(400)
        bio = io.BytesIO()
        file.save(bio)
        bio.seek(0, 0)
        try:
            image = Image.open(bio)
        except UnidentifiedImageError:
            abort(400)
        except Image.DecompressionBombError:
            return ErrorHandler(error.HTTPError(400, "PNG Bomb Detected"))
        w = image.width
        h = image.height
        if w*h > 16777216:
            return ErrorHandler(error.HTTPError(400, "Image too big!"))
        if textureType == "skin":
            mp = w / 64
            if mp < 1 or mp != math.floor(mp):
                abort(400)
            hp = h / 32
            if hp/mp != 1 and hp/mp != 2:
                abort(400)
            tt = False
        else:
            mp = w / 64
            if mp < 1 or mp != math.floor(mp):
                mp = w / 22
                if mp < 1 or mp != math.floor(mp):
                    abort(400)
                wp = h / 17
                if mp/wp != 1:
                    abort(400)
                tt = True
            else:
                wp = h / 32
                if mp/wp != 1:
                    abort(400)
                tt = False
        if tt:
            mi = max(math.ceil(w/64), math.ceil(h/32))
            img = Image.new((64*mi, 32*mi), "RGBA")
            img.paste(image)
            s = io.BytesIO()
            img.save(s, "png")
        else:
            s = io.BytesIO()
            image.save(s, "png")
        s.seek(0,0)
        file_content = s.read()
        hashes = upload.ImageHash(file_content)
        wrte = open("./Skins/%s.png"%hashes, "wb")
        wrte.write(file_content)
        wrte.close()
        if textureType == "skin":
            textureobj.SkinModify(textureType, config.domain+"/textures/"+hashes, {"model": model})
        else:
            textureobj.SkinModify(textureType, config.domain + "/textures/" + hashes)
        npld = json.dumps(pdata.serialize())
        pfd.serialized_data = npld
        db.session.commit()
        return ErrorHandler(error.HTTP204())
    else:
        textureobj.deleteSkin(textureType)
        npld = json.dumps(pdata.serialize())
        pfd.serialized_data = npld
        db.session.commit()
        return ErrorHandler(error.HTTP204())

@app.route("/textures/<uuid>", methods=["GET"])
def tex(uuid):
    for x in uuid:
        if x not in "0123456789abcdef":
            abort(404)
    try:
        fs = open("./Skins/%s.png"%uuid, "rb")
        rsp = Response(fs.read(), 200)
        rsp.headers["Content-Type"] = "image/png"
        return rsp
    except FileNotFoundError:
        abort(404)

#Extra API
@app.route("/", methods=["GET"])
def root():
    base = {}
    rtd = {}
    if config.implementationName != None:
        rtd["implementationName"] = config.implementationName
    if config.implementationVersion != None:
        rtd["implementationVersion"] = config.implementationVersion
    if config.serverName != None:
        rtd["serverName"] = config.serverName
    if config.links_homepage != None or config.links_register != None:
        ls = {}
        if config.links_homepage != None:
            ls["homepage"] = config.links_homepage
        if config.links_register != None:
            ls["register"] = config.links_register
        rtd["links"] = ls
    rtd["feature.non_email_login"] = config.no_email_login
    rtd["feature.legacy_skin_api"] = config.legacy_skin_api
    rtd["feature.no_mojang_namespace"] = config.no_mojang_space
    rtd["feature.enable_mojang_anti_features"] = config.enable_anti_features
    base["meta"] = rtd
    base["skinDomains"] = config.skindomains
    base["signaturePublickey"] = clas.get_pub()
    rs = Response(json.dumps(base), 200)
    rs.headers["Content-Type"] = "application/json, charset=utf-8"
    return rs

#app.run(config.host, config.port)
