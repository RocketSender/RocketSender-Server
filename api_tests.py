from requests import get, post

URL = 'https://127.0.0.1:8080/'

# --------------------------initiate_registration--------------------
post(URL + 'initiate_registration')  # 'Empty request'
post(URL + 'initiate_registration', json={'asd': 'f'})  # 'Bad request'
post(URL + 'initiate_registration', json={'email': 'tewsdsdf'})  # 'Send error'
post(URL + 'initiate_registration', json={'email': 'EMAIL@mail.ru'})  # 'OK'
post(URL + 'initiate_registration', json={'email': 'EMAIL@mail.ru'})  # 'Email is already registered'

# --------------------------complete_registration--------------------
post(URL + 'complete_registration')  # 'Empty request'
post(URL + 'complete_registration', json={'asd': 'asd'})  # 'Bad request'
post(URL + 'complete_registration',
     json={'email': 'EMAIL@test.ru', 'password': 'UserPassword1', 'public_key': 'user_public_key', 'token': 1234567,
           'login': 'user_login'})  # 'OK'

post(URL + 'complete_registration',
     json={'email': 'EMAIL@test.ru', 'password': 'UserPassword1', 'public_key': 'user_public_key', 'token': 1234567,
           'login': 'exist_user'})  # 'Login already exist
post(URL + 'complete_registration',
     json={'email': 'EMAIL@test.ru', 'password': 'UserPassword1', 'public_key': 'user_public_key', 'token': 'abc',
           'login': 'user_login'})  # 'Token error’

# --------------------------create_chat------------------------------
post(URL + 'create_chat')  # 'Empty request'
post(URL + 'create_chat', json={'sdf'})  # 'Bad request'
post(URL + 'create_chat',
     json={'login': 'bad_login', 'password': 'UserPassword1', 'user': '@testtest'})  # 'login/password is incorrect'
post(URL + 'create_chat',
     json={'login': 'correct_login', 'password': 'bad_password', 'user': '@testtest'})  # 'login/password is incorrect'
post(URL + 'create_chat',
     json={'login': 'correct_login', 'password': 'correct_password', 'user': '@bad_user'})  # 'Incorrect username'
post(URL + 'create_chat',
     json={'login': 'correct_login', 'password': 'correct_password', 'user': '@testtest'})  # 'OK'
post(URL + 'create_chat',
     json={'login': 'correct_login', 'password': 'correct_password', 'user': '@testtest'})  # 'Chat already exists'

# --------------------------get_user_chats---------------------------
get(URL + 'get_user_chats')  # 'Empty request'
get(URL + 'get_user_chats', json={'asd': 'asd'})  # 'Bad request'
get(URL + 'get_user_chats', json={'login': 'bad_login', 'password': 'UserPassword1'})  # 'login/password is incorrect'
get(URL + 'get_user_chats',
    json={'login': 'correct_login', 'password': 'bad_password'})  # 'login/password is incorrect'
get(URL + 'get_user_chats', json={'login': 'correct_login', 'password': 'correct_password'})  # 'OK'

# --------------------------get_user_chats---------------------------
get(URL + 'get_user_data')  # 'Empty request'
get(URL + 'get_user_data', json={'asd': 'asd'})  # 'Bad request'
get(URL + 'get_user_data', json={'login': 'bad_login', 'password': 'UserPassword1'})  # 'login/password is incorrect'
get(URL + 'get_user_data',
    json={'login': 'correct_login', 'password': 'bad_password'})  # 'login/password is incorrect'
get(URL + 'get_user_data', json={'login': 'correct_login', 'password': 'correct_password'})  # 'OK'

# --------------------------send_message-----------------------------
post(URL + 'send_message')  # 'Empty request'
post(URL + 'send_message', json={'sdf': 'asd'})  # 'Bad request'
post(URL + 'send_message',
     json={'login': 'correct_login', 'password': 'UserPassword1', 'type': 1, 'data': 'encrypted_data',
           'signature': 'message_signature', 'chat_id': 'correct_chat_id',
           'keys': '{"username1": "key1", "username2": "key2"}'})  # 'OK'
post(URL + 'send_message',
     json={'login': 'bad_login', 'password': 'UserPassword1', 'type': 1, 'data': 'encrypted_data',
           'signature': 'message_signature', 'chat_id': 'correct_chat_id',
           'keys': '{"username1": "key1", "username2": "key2"}'})  # 'login/password is incorrect'
post(URL + 'send_message',
     json={'login': 'correct_login', 'password': 'bad_password', 'type': 1, 'data': 'encrypted_data',
           'signature': 'message_signature', 'chat_id': 'correct_chat_id',
           'keys': '{"username1": "key1", "username2": "key2"}'})  # 'login/password is incorrect'
post(URL + 'send_message',
     json={'login': 'correct_login', 'password': 'UserPassword1', 'type': 10, 'data': 'encrypted_data',
           'signature': 'message_signature', 'chat_id': 'correct_chat_id',
           'keys': '{"username1": "key1", "username2": "key2"}'})  # 'Incorrect message type'
post(URL + 'send_message',
     json={'login': 'correct_login', 'password': 'UserPassword1', 'type': 1, 'data': 'encrypted_data',
           'signature': 'message_signature', 'chat_id': 'bad_chat_id',
           'keys': '{"username1": "key1", "username2": "key2"}'})  # 'Chat not found'
post(URL + 'send_message',
     json={'login': 'correct_login', 'password': 'UserPassword1', 'type': 1, 'data': '',
           'signature': 'message_signature', 'chat_id': 'correct_chat_id',
           'keys': '{"username1": "key1", "username2": "key2"}'})  # 'Empty data'
post(URL + 'send_message',
     json={'login': 'correct_login', 'password': 'UserPassword1', 'type': 1, 'data': 'encrypted_data',
           'signature': 'message_signature', 'chat_id': 'correct_chat_id',
           'keys': 'asdas'})  # 'Json keys error'

# --------------------------get_public_key-----------------------------
get(URL + 'get_public_key')  # 'Empty request'
get(URL + 'get_public_key', json={'sdf': 'asd'})  # 'Bad request'
get(URL + 'get_public_key',
    json={'login': 'bad_login', 'password': 'UserPassword1', 'username': '@testtest'})  # 'login/password is incorrect'
get(URL + 'get_public_key', json={'login': 'correct_login', 'password': 'bad_password',
                                  'username': '@testtest'})  # 'login/password is incorrect'
get(URL + 'get_public_key',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'username': 'bad_username'})  # 'User not found'
get(URL + 'get_public_key',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'username': '@testtest'})  # 'OK'

# --------------------------get_all_messages-------------------------
get(URL, 'get_all_messages')  # 'Empty request'
get(URL, 'get_all_messages', json={'sdf': 'asd'})  # 'Bad request'
get(URL, 'get_all_messages',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'chat_id': 'correct_chat_id'})  # 'OK'
get(URL, 'get_all_messages', json={'login': 'bad_login', 'password': 'UserPassword1',
                                   'chat_id': 'correct_chat_id'})  # 'login/password is incorrect'
get(URL, 'get_all_messages', json={'login': 'correct_login', 'password': 'bad_password',
                                   'chat_id': 'correct_chat_id'})  # 'login/password is incorrect'
get(URL, 'get_all_messages',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'chat_id': 'bad_chat_id'})  # 'Chat not found'
get(URL, 'get_all_messages',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'chat_id': 'other_chat_id'})  # 'No access'

# --------------------------get_last_messages------------------------
get(URL, 'get_last_messages')  # 'Empty request'
get(URL, 'get_last_messages', json={'sdf': 'asd'})  # 'Bad request'
get(URL, 'get_last_messages',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'chat_id': 'correct_chat_id'})  # 'OK'
get(URL, 'get_last_messages', json={'login': 'bad_login', 'password': 'UserPassword1',
                                    'chat_id': 'correct_chat_id'})  # 'login/password is incorrect'
get(URL, 'get_last_messages', json={'login': 'correct_login', 'password': 'bad_password',
                                    'chat_id': 'correct_chat_id'})  # 'login/password is incorrect'
get(URL, 'get_last_messages',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'chat_id': 'bad_chat_id'})  # 'Chat not found'
get(URL, 'get_last_messages',
    json={'login': 'correct_login', 'password': 'UserPassword1', 'chat_id': 'other_chat_id'})  # 'No access'
