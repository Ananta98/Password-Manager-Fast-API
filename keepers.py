import os, binascii, secrets, base64
import codecs
from database import *
from authentication import *
from pydantic import BaseModel
from fastapi import Depends, APIRouter, HTTPException, status

import pyaes
from cryptography.fernet import Fernet

router = APIRouter()

class passkeeper(BaseModel):
    linkname : str = None
    username : str = ""
    password : str = ""

def password_encrypt_Fernet(secret_key, plain_password):
    fernet = Fernet(secret_key)
    return fernet.encrypt(plain_password)

def password_decrypt_Fernet(secret_key, encrypted_password):
    fernet = Fernet(secret_key)
    return fernet.decrypt(encrypted_password)

@router.get('/passkeeper')
async def get_passkeeper(current_user : User = Depends(get_current_active_user)):
    current_user = get_user(current_user['username'])
    all_keepers = get_all_passkeeper(current_user['id'])
    return all_keepers

@router.post('/passkeeper/insert')
async def insert_passkeeper(new_passkeeper : passkeeper, current_user : User = Depends(get_current_active_user)):
    current_user = get_user(current_user['username'])
    with open(f"{current_user['username']}-secretkey-fernet.bin","rb") as f:
        secret_key = f.read()
    encrypted_linkname = password_encrypt_Fernet(secret_key,new_passkeeper.linkname.encode('utf-8'))
    encrypted_username = password_encrypt_Fernet(secret_key,new_passkeeper.username.encode('utf-8'))
    encrypted_password = password_encrypt_Fernet(secret_key,new_passkeeper.password.encode('utf-8'))
    insert_keeper_database(current_user['id'],encrypted_linkname,encrypted_username,binascii.hexlify(encrypted_password))
    return {'message' : 'Success add keeper'}

@router.get('/passkeeper/decrypt/{passkeeper_id}')
async def decrypt_passkeeper(passkeeper_id : str, current_user : User = Depends(get_current_active_user)):
    current_user = get_user(current_user['username'])
    result = get_passkeeper_id_exist_in_user(current_user['id'],passkeeper_id)
    if result == None:
        raise HTTPException(status_code=400,detail="Data doesn't Exist")
    with open(f"{current_user['username']}-secretkey-fernet.bin","rb") as f:
        secret_key = f.read()
    decrypted_linkname = password_decrypt_Fernet(secret_key,result['linkname'].encode('utf-8'))
    decrypted_username = password_decrypt_Fernet(secret_key,result['username'].encode('utf-8'))
    decrypted_password = password_decrypt_Fernet(secret_key,binascii.unhexlify(result['password']))
    return {"decrypted-linkanme" : decrypted_linkname, "decrypted-username" : decrypted_username, "decrypted-passsword" : decrypted_password}

@router.delete('/passkeeper/delete')
async def delete_passkeeper(passkeeper_id : str, current_user : User = Depends(get_current_active_user)):
    current_user = get_user(current_user['username'])
    result = get_passkeeper_id_exist_in_user(current_user['id'],passkeeper_id)
    if result == None:
        raise HTTPException(status_code=400,detail="Data doesn't Exist")
    delete_keeper(passkeeper_id)
    return {"Message" : "Passkeeper Success Deleted"}