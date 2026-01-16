import os
import hashlib
import base64

key = os.urandom(64)
hash_func = lambda x: hashlib.sha256(x).hexdigest()

class PATIENT_BOY:
    def __init__(self):
        self.name = None
        self.queue_number = 2 ** 512

    def advance(self):
        self.queue_number -= 1
        if self.queue_number == 0:
            print("WOW! YOU'VE BEEN A VERY PATIENT BOY! WELCOME TO THE END OF THE LINE.")
            print(open("flag.txt").read())

    def __str__(self):
        return f'name={self.name};queue_number={self.queue_number}'

def convert_identification_to_class(s):
    boy = PATIENT_BOY()
    for i in s.split(b';'):
        # in case anyone wants to submit malformed identifications....
        try:
            key, val = i.split(b'=')
            key = key.decode(errors='ignore')
            val = val.decode(errors='ignore')
            if key in boy.__dict__:
                if key == 'queue_number':
                    val = int(val)
                setattr(boy, key, val)
        except:
            pass
    return boy

def check_name(name):
    for char in name:
        if char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            return False
    return True

def menu(user=None):
    print(
        '\nPATIENT BOY WAITING ROOM INCORPORATED\n',
        '----\n',
        'WORLD IS A WAIT\n',
        'WAIT EM ALL 1989\n',
        'I AM PATIENT BOY\n',
        '9523432834095834095834 MAN HOURS WASTED\n',
        '----\n',
        '1. JOIN THE LINE.\n',
        '2. START FROM WHERE YOU LEFT OFF.\n',
        '3. KEEP GOING DOWN THE LINE.\n',
        '4. ACQUIRE IDENTIFICATION.\n'
    )

    try:
        choice = int(input('WHAT IS YOUR CHOICE. > '))
        if choice == 1:
            name = input('ENTER YOUR NAME PLEASE. > ')
            assert check_name(name), "THAT'S AN ODD LOOKING NAME YOU HAVE."
            boy = PATIENT_BOY()
            boy.name = name
            print(f'WELCOME TO THE LINE. YOUR NAME IS {boy.name} AND YOU ARE {boy.queue_number} PLACES AWAY FROM THE FRONT.') 
            user = boy

        if choice == 2:
            message = input("PRESENT YOUR IDENTIFICATION. > ")
            msg_decoded = base64.b64decode(message.encode())
            print(msg_decoded)
            hash = input("PRESENT YOUR HASH. > ")
            assert hash_func(key + msg_decoded)  == hash, "YOU ARE AN IMPOSTOR. NO IMPOSTORS ALLOWED IN THE WAITING ROOM."
            user = convert_identification_to_class(msg_decoded)
            print(f'WELCOME BACK TO THE LINE. YOU ARE {user.name} AND YOU ARE {user.queue_number} PLACES AWAY FROM THE FRONT.')
            print('I WAIT, I WAIT, I WAIT, I WAIT.')

        if choice == 3:
            user.advance()
            print(f"YOU ARE NOW {user.queue_number} PLACES AWAY FROM THE LINE.")

        if choice == 4:
            message, hash = base64.b64encode(str(user).encode()), hash_func(key + str(user).encode())
            print(f"HERE IS YOUR IDENTIFICATION.")
            print(f"{message = }")
            print(f"{hash = }")
            print(f"PRESENT IT WHEN PROMPTED.")
    except Exception as e:
        print('GET BOOTED OUT OF THE LINE, BUDDY.')
        print(e)
        import traceback; traceback.print_exc()
        exit()
    return user

user = None
while True:
    user = menu(user)

