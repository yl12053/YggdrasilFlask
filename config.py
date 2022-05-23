#[General Setting]
uri = "127.0.0.1:3306/Yggdrasil"
base = "mysql"
host = "0.0.0.0"
port = 19090
domain = "http://unreve.top:19090"
binds = {
    "forum": "mysql+pymysql://sql_www_threenot:6xcKzKsTmHRp4yZB@8.210.100.123:3306/sql_www_threenot"
}

#[Cleaner Setting]
maximum_invalid_token = 5000

#[Yggdrasil Auth Setting]
rate = 1

#[Server Metadata Setting]
serverName = "MisakaNetwork Ethernet Yggdrasil Server"
implementationName = "MisakaNetwork-China/FlaskServer"
implementationVersion = "1a"
links_homepage = None
links_register = None
no_email_login = True
skindomains = [".unreve.top", "unreve.top", "localhost"]
legacy_skin_api = False
no_mojang_space = False
enable_anti_features = False

#[Yggdrasil Token Setting]
timeout_temp = 259200
timeout_revoke = 518400
allow_username_login = True
timeout_login = 180
maximum_amount_query_allowed = 300
maximum_pixel = 268435456

#[Yggdrasil Sign Key Setting]
private_key = "./keys/privKey.pem"

#[Mysql Setting]
user = "misakanetwork"
pas = "misakanetwork"

#[Auto Setting]
if base == "mysql":
    use = "mysql+pymysql://%s:%s@%s"%(user, pas, uri)
elif base == "sqlite":
    use = "sqlite://"+uri
