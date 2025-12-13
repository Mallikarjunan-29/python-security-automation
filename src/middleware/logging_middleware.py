from flask import request,g
import uuid


def add_logging_context():
    #Generate or get request ID
    g.request_id=request.headers.get('X-Request-ID',str(uuid.uuid4()))
    g.user_id="anonymous"
