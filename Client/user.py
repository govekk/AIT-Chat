from json import JSONEncoder
import os.path
from Crypto.PublicKey import RSA

class User():
    '''
    Represents a chat participant
    '''

    def __init__(self, user_name=""):
        '''
        Constructor
        :param user_name: the name of the user
        :return: instance
        '''
        self.user_name = user_name
        pair_file = user_name+'pair.pem'
        pub_file = user_name+'pub.pem'
        if not os.path.isfile(pair_file):
            key = RSA.generate(2048)
            ofile = open(pair_file, 'w')
            ofile.write(key.exportKey('PEM'))
            ofile.close()
            ofile = open(pub_file, 'w')
            ofile.write(key.publickey().exportKey('PEM'))
            ofile.close()


    def get_user_name(self):
        '''
        Return the user name
        :return: string
        '''
        return self.user_name

    def __str__(self):
        '''
        Returns the object as a string, invoked by the print and str() instructions
        :return: string
        '''
        return "\n[" + self.user_name + "]"

class UserEncoder(JSONEncoder):
    '''
    Class responsible for JSON encoding instances of the User class
    '''
    def default(self, o):
        '''
        Returns a Python object for JSON serialization
        :param o: should in an instance of the User class
        :return: dict
        '''
        assert isinstance(o, User)
        return o.__dict__