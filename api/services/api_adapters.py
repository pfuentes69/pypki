import json

from . import pki

def process_input(data):
    # Transform input if needed, pass to core logic
    result = "SOMETHING"
    return {"result": result}

def get_ca_collection_json():
    ca_list = pki.get_ca_collection()
    return ca_list

def get_ca_details_json(ca_id):
    ca_details = pki.get_ca_by_id(ca_id)
    return ca_details