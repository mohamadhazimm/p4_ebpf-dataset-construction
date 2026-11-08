import socket, time
end = time.time() + 20
buf = bytes(65536)
while time.time() < end:
    try:
        s = socket.create_connection(("10.0.0.1", 80), 2)
        s.sendall(b"POST /u HTTP/1.0\r\nContent-Length: 999999999\r\n\r\n")
        for _ in range(400):
            s.sendall(buf)
        s.close()
    except OSError:
        time.sleep(0.05)
