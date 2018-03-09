Users = [{
    'user_name': 'deep',
    'user_password': 123
}, {
    'user_name': 'nvd',
    'user_password': 556
}]


# def get_pw(user):
#     if user in Users['user_name']:
#         return user['user_password']
#     return None
#
#
# print(get_pw('deep'))

def get_pw(user, passw):
    for u in Users:
        if user in u['user_name']:
            if u['user_password'] == passw:
                return True
    return False

# a

print(get_pw('deep',123))