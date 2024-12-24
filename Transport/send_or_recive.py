def recive(active_conn, END_COMMAMD, BUFFER_SIZE):
    res = b""
    while True:
        buffer = active_conn.recv(BUFFER_SIZE)
        if END_COMMAMD in buffer:
            res += buffer.strip(END_COMMAMD)
            break
        else:
            res += buffer

    return res