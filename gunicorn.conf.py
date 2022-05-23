import multiprocessing
import config as c

bind = "%s:%s"%(c.host, c.port)
chdir = "/Yggdrasil"
worker_class = "eventlet"
workers = 1
threads= 1
loglevel = "info"
access_log_format = '%(t)s %(p)s %(h)s "%(r)s" %(s)s %(L)s %(b)s %(f)s" "%(a)s"'
accesslog = chdir+"/access.log"
errorlog = chdir+"/error.log"
