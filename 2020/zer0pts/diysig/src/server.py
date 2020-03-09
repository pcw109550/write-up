import socketserver
import socket
from diysig import DIYSig

class DIYSigHandler(socketserver.BaseRequestHandler, object):
    def recvline(self):
        sock = self.request
        result = b''
        while True:
            b = sock.recv(1)
            if b is None or b == b'\n':
                break
            result += b
        return result
    
    def menu(self):
        sock = self.request
        sock.send(b"=-=-=-=-= DIYSig =-=-=-=-=\n")
        sock.send(b"[1] Encrypt and Sign\n")
        sock.send(b"[2] Verify Encrypted Mesasge\n")
        sock.send(b"[3] Public Key Disclosure\n")
        sock.send(b"> ")
        opt = self.recvline()
        try:
            return int(opt)
        except:
            return None

    def encsig(self):
        sock = self.request
        b2s = lambda ba: ''.join(list(map(chr, ba)))
        s2b = lambda st: b''.join(list(map(lambda c: bytes([ord(c)]), list(st))))
        
        sock.send(b"MSG : ")
        msg = self.recvline()
        if msg is None:
            return
        
        try:
            if len(msg) % 2 == 1:
                msg = b'0' + msg
            m = int.from_bytes(bytes.fromhex(b2s(msg)), byteorder='big')
            s = DIYSig()
            E, H = s.encsig(m)
        except Exception as e:
            print("[encsig] {}".format(e))
            return

        sock.send(s2b("ENC : {:x}\n".format(E)))
        sock.send(s2b("SIG : {:08x}\n".format(H)))
            
    def verify(self):
        sock = self.request
        b2s = lambda ba: ''.join(list(map(chr, ba)))
        s2b = lambda st: b''.join(list(map(lambda c: bytes([ord(c)]), list(st))))
        
        sock.send(b"ENC : ")
        enc = self.recvline()
        sock.send(b"SIG : ")
        sig = self.recvline()
        if enc is None or sig is None:
            return
        
        try:
            if len(enc) % 2 == 1:
                enc = b'0' + enc
            c = int.from_bytes(bytes.fromhex(b2s(enc)), byteorder='big')
            h = int.from_bytes(bytes.fromhex(b2s(sig)), byteorder='big')
            s = DIYSig()
            H = s.getsig(c)
        except Exception as e:
            print("[verify] {}".format(e))
            return
        
        if h == H:
            sock.send(b"Signature OK!\n")
        else:
            sock.send(s2b("Invalid Signature: {:08x} != {:08x}\n".format(h, H)))

    def disclose(self):
        sock = self.request
        s2b = lambda st: b''.join(list(map(lambda c: bytes([ord(c)]), list(st))))

        s = DIYSig()
        n, e = s.pubkey()
        sock.send(b"[PUBKEY]\n")
        sock.send(s2b(" N := {:x}\n".format(n)))
        sock.send(s2b(" E := {:x}\n".format(e)))

    def handle(self):
        opt = self.menu()
        if opt is None:
            return
        
        if opt == 1:
            self.encsig()
        elif opt == 2:
            self.verify()
        elif opt == 3:
            self.disclose()

class DIYSigServer(socketserver.ThreadingTCPServer, object):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

if __name__ == '__main__':
    HOST, PORT = ("127.0.0.1", 3001)
    server = DIYSigServer((HOST, PORT), DIYSigHandler)
    server.serve_forever()
