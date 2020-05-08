def check_password(passwd):

    if len(passwd) < 8:
        return False

    if not any(char.isdigit() for char in passwd):
        return False

    if not any(char.isupper() for char in passwd):
        return False

    if not any(char.islower() for char in passwd):
        return False

    with open('pass.txt') as f:
        dic = f.readlines()

    if passwd in dic:
        return False

    return True
