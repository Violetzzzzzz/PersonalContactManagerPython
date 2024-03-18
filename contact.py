class Contact:
    id = None
    name = None
    phone_number = None
    email = None
    
    def __init__(self, id, name):
        self.id = id
        self.name = name
       

    def set_number(self, phone_number):
        self.phone_number = phone_number

    def set_email(self, email):
        self.email = email

    
