import http.server
import socketserver
import requests
from easysettings import EasySettings
from gop import FileLayer

settings = EasySettings("gop.conf")

class Server(socketserver.TCPServer):
    # Avoid "address already used" error when frequently restarting the script
    allow_reuse_address = True


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200, "OK")
        code = self.path.split("code=")[1]
        r = requests.get(FileLayer().load_base_url() + "/login/github?code=" + code)
        self.end_headers()
        if r.status_code == 200:
            settings.set("token", str(r.content, 'utf-8'))
            settings.save()
            print("Successfully logged in!")
            self.wfile.write("You were logged in successfully, you can now close this tab :)".encode("utf-8"))
        else:
            self.wfile.write("Something went wrong :(".encode("utf-8"))
