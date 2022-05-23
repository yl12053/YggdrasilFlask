from PIL import Image
import io
import struct
import hashlib
import os
import platform
import subprocess
import base64

def ImageHash(img_data):
    arc = list(platform.architecture())
    if arc[1] == "":
        arc[1] = {"Linux":"ELF", "Windows":"WindowsPE", "Darwin":""}.get(platform.system())
    if arc[1] == None:
        arc[1] = ""
    img = Image.open(io.BytesIO(img_data))
    if os.path.exists("./bins/"+''.join(arc)): #compiled fast version
        if img.mode != "RGBA":
            n = io.BytesIO()
            img.convert("RGBA")
            img.save(n, "png")
            sd = base64.b64encode(n.getvalue())
        else:
            sd = base64.b64encode(img_data)
        npc = subprocess.Popen("./bins/"+''.join(arc)+"/upload", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        d, e = npc.communicate(b'%d\n%s\n'%(len(sd), sd))
        if len(d) == 64:
            return d.decode()
    else:
        if img.mode != "RGBA":
            img.convert("RGBA")
    buf = b"" #pure python version
    buf += struct.pack(">I", img.width)
    buf += struct.pack(">I", img.height)
    for x in range(img.width):
        for y in range(img.height):
            pdt = img.getpixel((x, y))
            if pdt[3] == 0:
                buf += b'\x00\x00\x00\x00'
            else:
                buf += struct.pack("BBBB", pdt[3], pdt[0], pdt[1], pdt[2])
    return hashlib.sha256(buf).hexdigest().lower()