from message import Message
from time import sleep
from threading import Thread
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
import base64

state = 'CHAT';
key = b'0123456789abcdef0123456789abcdef'
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
        self.id = c_id  # ID of the conversation
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
        
        '''
                # Queries the server for the conversations of the current user (user is a participant)
        req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/conversations")
        # Include Cookie
        req.add_header("Cookie", self.manager.cookie)
        r = urllib2.urlopen(req)
        
        conversations = json.loads(r.read())
        # Sets list of participants upon finding matching conversation id
        for c in conversations:
            if self.id == c["conversation_id"]:
                self.participants = c["participants"] # list of participants in the conversation
                
        self.initiator = self.participants[-1]; # if list is >1, initiator is last
        '''


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
        '''
        global state == 'CRYPTO';
        #HOW TO TELL IF A USER IS THE INITIATOR: state = CREATE_CONVERSATION
        current_user = self.manager.user_name #name of current user
        
        if current_user == self.initiator:
            master_key = Random.new().read(AES.block_size)
        else:
            self.process_outgoing_message("Here's my nonce, encrypted with initiator's public key!")'''
            
        
        # You can use this function to initiate your key exchange
		# Useful stuff that you may need:
		# - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_user()
        # You may need to send some init message from this point of your code
		# you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
		# replace this with anything needed for your key exchange 
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

        # process message here
		# example is base64 decoding, extend this with any crypto processing of your protocol
		# decode the message with AES
        global key
        #msg_type = msg_raw[1:] # gets bit designating chat state when message was sent
        iv = msg_raw[:AES.block_size]
        msg_raw = msg_raw[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decoded_msg = cipher.decrypt(msg_raw)   
        decoded_msg = decoded_msg[:len(decoded_msg)-ord(decoded_msg[-1])]

        # signature verification

        # message sent in chat state
        '''
        if msg_type == 0:
            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=decoded_msg,
                owner_str=owner_str)
        elif msg_type == 1;
            # message sent in crypto state
            # if user is the initiator, checks user's public key with
            # those of eligible participants. If its correct, send the master key
            
            
            #PSEUDO CODE: initiator sends group key
            if encryption == user.public_key && user = self.initiator {
                # Master key is encrypted with key user's nonce and public key of user (and initiator?)
                self.process_outgoing_message("Sending the master key!");
            }
        elif msg_type == 1 && state == 'CRYPTO':
            #PSEUDO CODE: User waiting for master key that has intercepted a crypto message
            msg_sig = self.initiator.public_key # make sure that the initiator sent the message
            master key = decoded_msg    # make this the global key??
            state = 'CHAT'                # has master key, may now read all chats
            '''
            

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''
        if state == 'CHAT': 
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
            global key
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encoded_msg = iv+cipher.encrypt(msg_raw) # add '0' to front to indicate its a chat message

            #add the digital signature here onto the hashed message

            # post the message to the conversation
            self.manager.post_message_to_conversation(encoded_msg)
        '''
        elif state == 'CRYPTO':
            #TLS padding here
            plength = AES.block_size - (len(msg_raw)%AES.block_size)
            msg_raw += chr(plength)*plength

            # process outgoing message here
            # encode the message with AES\
            iv = Random.new().read(AES.block_size)
            global key
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encoded_msg = '1'+iv+cipher.encrypt(msg_raw) # 1 indicates its a crypto message

            #add the digital signature here onto the hashed message
            '''

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
