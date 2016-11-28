from config import *
import urllib2
import json
from message import Message
from time import sleep
from threading import Thread
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import os
import base64

conv_state = 'CRYPTO'
master_key =''
nonce=''
msg_type='0'

past_messages = []

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = str(c_id)  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True
        
        
        # Queries the server for the conversations of the current user (user is a participant)
        req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations")
        # Include Cookie
        req.add_header("Cookie", self.manager.cookie)
        r = urllib2.urlopen(req)
        
        conversations = json.loads(r.read())
        
        # Sets list of participants upon finding matching conversation id
        for c in conversations:
            if self.id == str(c["conversation_id"]):
                self.participants = c["participants"] # list of participants in the conversation
        self.initiator = str(self.participants[-1]); # if list is >1, initiator is last
        


    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)
                

        

    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''
        global master_key
        global conv_state
        global nonce
        global msg_type 
        # set state as chat if there does exist a master key file and then go to processing outgoing messages   
        if os.path.isfile('./master_key_'+self.id+'_'+self.manager.user_name+'.txt'):
            master_key_file = open('master_key_'+self.id+'_'+self.manager.user_name+'.txt','r')
            master_key=master_key_file.read()
            master_key_file.close()
            conv_state ='CHAT'
            msg_type = '0'
            pass
        #set state as crypto if there doesnt exist a master key file
        else:
            
            current_user = self.manager.user_name #name of current user

            if current_user == self.initiator:
                #generate a master key using a nonce
                master_key=Random.new().read(AES.block_size)                
                #save master key to a file
                master_key_file = open('master_key_'+self.id+'_'+self.manager.user_name+'.txt','w')
                master_key_file.write(master_key)
                master_key_file.close()
                conv_state='CHAT'
                msg_type='1'
                                           
                
            else:
                #generate a nonce
                nonce=Random.new().read(16)
                conv_state = 'CRYPTO'
                self.process_outgoing_message('1'+nonce)
                msg_type='1'
                                           
        pass


    def process_incoming_message(self, msg_raw, msg_id, owner_str):
                                        
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''
        global conv_state
        global master_key
        global past_messages
        global nonce
        global msg_type
        
        # message sent in chat state
        msg_type = msg_raw[0]
        msg_raw = msg_raw[1:]

                    
        #sending master key
        if msg_type == '0' and conv_state == 'CRYPTO':
            msg_list = ['0'+msg_raw, msg_id, owner_str]
            past_messages.append(msg_list)
        if msg_type == '0' and conv_state == 'CHAT':
                        
            # remove 344first characters to get encoded signature
            signature = msg_raw[:344]
            # decode signature
            signature_dec = str(base64.b64decode(signature))
                                           
            msg_raw = msg_raw[344:]
            # retrieve sender's public key
            pubkeystr = self.manager.retrieve_public_key(owner_str)
            pubkey = RSA.importKey(pubkeystr)
            # new hash
            h = SHA256.new()
            h.update(msg_raw)
            verifier = PKCS1_v1_5.new(pubkey)
            
            # if signature is correct
            if verifier.verify(h, signature_dec):
                # decode the message with AES
                #msg_type = msg_raw[1:] # gets bit designating chat state when message was sent
                iv = msg_raw[:AES.block_size]
                msg_raw = msg_raw[AES.block_size:]
                cipher = AES.new(master_key, AES.MODE_CBC, iv)
                decoded_msg = cipher.decrypt(msg_raw)   
                decoded_msg = decoded_msg[:len(decoded_msg)-ord(decoded_msg[-1])]
                                           

                #print message and add it to the list of printed messages
                self.print_message(
                    msg_raw=decoded_msg,
                    owner_str=owner_str
                    )
            # if signature is not correct
            else:
                print self.manager.user_name + " failed to authenticate " + owner_str + ". Message will not be printed."
                
        elif msg_type == '1' and conv_state == 'CHAT':
            # message sent in chat state
            # if user is the initiator, checks user's public key with
            # those of eligible participants. If its correct, send the master key
            if owner_str == self.manager.user_name:
                return
            if self.manager.retrieve_public_key(owner_str) and self.manager.user_name==self.initiator:
                #encrypt nonce + master key and signature
                #owner_str is the person who sent the nonce
                
                pubkeystr = self.manager.retrieve_public_key(owner_str)
                pubkey = RSA.importKey(pubkeystr)
                cipher = PKCS1_OAEP.new(pubkey)
                master_key_enc = base64.b64encode(cipher.encrypt(str(self.manager.user_name)+master_key))
                sent_nonce = msg_raw
                #generate signature using initiator's private key
                kfile = open(self.manager.user_name+'_pairKey.pem')
                privkeystr = kfile.read()
                kfile.close()
                privkey = RSA.importKey(privkeystr)
                #make a hash and hash the message 
                h = SHA256.new()
                h.update(str(owner_str)+sent_nonce+master_key_enc)
                signer = PKCS1_v1_5.new(privkey)
                # sign and encrypt the master key
                signature = signer.sign(h)
                signature_key = str(base64.b64encode(signature))

                master_key_send = '1'+sent_nonce+signature_key+master_key_enc

                conv_state = 'CRYPTO'
                self.process_outgoing_message(master_key_send)
                conv_state = 'CHAT'
            
                                           
        elif msg_type == '1' and conv_state == 'CRYPTO':
            #crypto state
            if owner_str == self.manager.user_name:
                return
            if self.manager.retrieve_public_key(owner_str):
                nonce_received =msg_raw[:16]
                if nonce_received == nonce:
                    sig_ver=msg_raw[16:360]
                    msg_raw=msg_raw[360:]
                    #verify the signature
                    signature_dec = str(base64.b64decode(sig_ver))
                    # retrieve sender's public key
                    pubkeystr = self.manager.retrieve_public_key(owner_str)
                    pubkey = RSA.importKey(pubkeystr)
                    # new hash
                    h = SHA256.new()
                    h.update(str(self.manager.user_name)+nonce+msg_raw)
                    verifier = PKCS1_v1_5.new(pubkey)
                    if verifier.verify(h, signature_dec):
                        #decrypt msg_raw
                        kfile = open(self.manager.user_name+'_pairKey.pem')
                        privkeystr = kfile.read()
                        kfile.close()
                        privkey = RSA.importKey(privkeystr)
                        cipher = PKCS1_OAEP.new(privkey)
                        master_key_receive=cipher.decrypt(base64.b64decode(msg_raw))
                        owner_len=len(owner_str)
                        if owner_str == master_key_receive[:owner_len]:
                            master_key=master_key_receive[owner_len:]                                      
                            #save master key to a file
                            master_key_file = open('master_key_'+self.id+'_'+self.manager.user_name+'.txt','w')
                            master_key_file.write(master_key)
                            master_key_file.close()
                        
                            conv_state='CHAT'
                            for message in past_messages:
                                self.process_incoming_message(msg_raw=message[0],
                                                      msg_id=message[1],
                                                      owner_str=message[2])


            

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''
        global conv_state
        global master_key
        global nonce
        
        if conv_state == 'CHAT': 
            # if the message has been typed into the console, record it, so it is never printed again during chatting
            if originates_from_console == True:
                # message is already seen on the console
                m = Message(
                    owner_name=self.manager.user_name,
                    content=msg_raw
                )
                self.printed_messages.append(m)


            #TLS padding here
            plength = AES.block_size - (len(msg_raw)%AES.block_size)
            msg_raw += chr(plength)*plength

            # process outgoing message here
            # encode the message with AES\
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(master_key, AES.MODE_CBC, iv)
            encoded_msg = iv+cipher.encrypt(msg_raw) # add '0' to front to indicate its a chat message

            # Sign message
            
            #read the private key of the user
            #key = RSA.importKey(open('privkey.der').read())
            kfile = open(self.manager.user_name+'_pairKey.pem')
            privkeystr = kfile.read()
            kfile.close()
            privkey = RSA.importKey(privkeystr)
            #make a hash and hash the message with the padding and iv
            h = SHA256.new()
            h.update(encoded_msg)
            signer = PKCS1_v1_5.new(privkey)
            # sign and encrypt the message; encrypted signature is 344 char long
            signature = signer.sign(h)
            signature_enc = str(base64.b64encode(signature))
            
            # append signature to front of encoded message
            encoded_msg = signature_enc + encoded_msg
            encoded_msg = '0' + encoded_msg
            # post the message to the conversation
            self.manager.post_message_to_conversation(encoded_msg)
            
                                            
        elif conv_state == 'CRYPTO':
            #first the nonce is received so the message has +1 in front of it
            #end it to incoming message and send back the master key encrypted with public key of person
            #then receive master key and decrypt it 
            #master key is already signed with the digital signature
            #other user must send nonce
            #if a nonce is received go to incoming message which will
            #actually send the message
            if msg_raw[0] == '1':
                m = Message(
                    owner_name=self.manager.user_name,
                    content=msg_raw
                )
                self.printed_messages.append(m)
                self.manager.post_message_to_conversation(msg_raw)
                #post message to conversation here
            #if nonce was not received in the crypto phase send error
            else:
                pass              
                
                                           

                                           
            


    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        # ADD REPLAY PREVENTION; msg id must be + 1 greater than prior message id
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)
