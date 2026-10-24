callback = None


def set_callback(new_callback):
    global callback
    callback = new_callback


def remote_print(message):
    print(message, flush=True)

    if callback:
        try:
            callback(str(message))
        except Exception:
            pass