import random
import string

def generate_random_password(length=8):
    #method to generate a random password if not provided
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))
