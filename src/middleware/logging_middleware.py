from flask import request,g
import uuid


def add_logging_context():
    #Generate or get request ID
    g.request_id=request.headers.get('X-Request-ID',str(uuid.uuid4()))
    if not hasattr(g, "user_id") or not g.user_id:
        g.user_id = "anonymous"
