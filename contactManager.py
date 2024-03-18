#!/usr/bin/python3
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import mysql.connector
import re
import os
import hashlib
from PIL import Image, ImageTk
from contact import Contact
from user import User

db_host=''
db_port=3306
db_user='admin'
db_password=''
db_database='db_python'

key_path = 'key.bin'
if os.path.exists(key_path):
    with open(key_path, 'rb') as file:
       bytes_data = file.read()
       key = bytes_data
else:
    random_pass_bytes = os.urandom(16)
    with open(key_path, 'xb') as file:
       file.write(random_pass_bytes)
    
root = tk.Tk()
from ce_style import CEStyle
home_frm = tk.Frame(root, padx=10, pady=10)
register_frm = tk.Frame(root, padx=10, pady=10)
login_frm = tk.Frame(root, padx=10, pady=10)
user_frm = tk.Frame(root, padx=10, pady=10)

contacts_list = list()
contact_row_mapping = []

def switch_page(new_frame, current_frame):
    if current_frame==register_frm:
        set_registerpage()
    elif current_frame==login_frm:
        set_loginpage
    if new_frame==user_frm:
        set_userpage()
    elif new_frame==home_frm:
        login_user = None;      
    current_frame.pack_forget()
    new_frame.pack(side="top", fill="both", expand=True)

def switch_func(view_frm, new_contact_frm, edit_contact_frm, func):
    if func=="new":
        if new_contact_frm.winfo_ismapped():
            new_contact_frm.pack_forget()
        if edit_contact_frm.winfo_ismapped():
            edit_contact_frm.pack_forget()
        set_new_contact_frame(view_frm, new_contact_frm, edit_contact_frm)
        view_frm.pack_forget()
        new_contact_frm.pack()
    elif func=="newback":
        set_viewfrm(view_frm, new_contact_frm, edit_contact_frm)
        new_contact_frm.pack_forget()
        view_frm.pack()
    elif func=="editback":
        set_viewfrm(view_frm, new_contact_frm, edit_contact_frm)
        edit_contact_frm.pack_forget()
        view_frm.pack()
    elif func=="edit":
        view_frm.pack_forget()
        edit_contact_frm.pack()
      

def search_button_clicked(search_entry, tree, contacts_label):
    search_name = search_entry.get()
    if not search_name:
        fill_treeview(tree)
        contacts_label.config(text=str(len(contacts_list))+" contacts")
    elif search_contact(search_name):
        fill_treeview(tree)
        searched_treeview(search_name, tree)
        contacts_label.config(text=str(len(contact_row_mapping))+" contacts")
    else:
        fill_treeview(tree)
        messagebox.showerror("Error", "Can't find contact: " + search_name)

def search_contact(search_name):
    for contact in contacts_list:
        if search_name.lower() in contact.name.lower():
            return True
    
    return False
    
def searched_treeview(search_name, tree):
    tree.delete(*tree.get_children())
    contact_row_mapping.clear()
    for contact in contacts_list:
        if search_name.lower() in contact.name.lower():
            row_id = tree.insert("", tk.END, values=(contact.name, contact.phone_number, contact.email))
            contact_row_mapping.append((contact, row_id))
        
def fill_treeview(tree):
    for item in tree.get_children():
        tree.delete(item)
    
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = "SELECT id, AES_DECRYPT(contact_name, %s) AS contact_name, AES_DECRYPT(contact_number, %s) AS contact_number, AES_DECRYPT(contact_email, %s) AS contact_email FROM `contacts` WHERE user_id = %s"
    cursor.execute(query, (key, key, key, login_user.id))
    results = cursor.fetchall()
    
    contacts_list.clear()
    contact_row_mapping.clear()
    
    for row in results:
        contact_id = row[0]  
        contact_name = row[1].decode('utf-8')
        contact_number = row[2].decode('utf-8')
        contact_email = row[3].decode('utf-8')
        contact = Contact(contact_id, contact_name)
        contact.set_number(contact_number)
        contact.set_email(contact_email)
        contacts_list.append(contact)
        row_id = tree.insert("", tk.END, values=(contact_name, contact_number, contact_email))
        contact_row_mapping.append((contact, row_id))
                                    
        
def check_contactname_format(entry, tip):
    name = entry.get()
    if not name:
        tip.config(
            text="Contact name cannot be empty.",
            fg="red"
        )
    else:
        tip.config(
            text="",
            fg="grey"
        )

def save_contact_db(contact_name, phone, email):
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = "INSERT INTO `contacts` (user_id, contact_name, contact_number, contact_email) VALUES (%s, AES_ENCRYPT(%s, %s), AES_ENCRYPT(%s, %s), AES_ENCRYPT(%s, %s))"
    user_id = login_user.id
    cursor.execute(query, (user_id, contact_name, key, phone, key, email, key))
    connection.commit()
    connection.close()
    
def update_contact_db(contact_name, phone, email, id):
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = (
        "UPDATE contacts SET "
        "contact_name = AES_ENCRYPT(%s, %s), "
        "contact_number = AES_ENCRYPT(%s, %s), "
        "contact_email = AES_ENCRYPT(%s, %s) "
        "WHERE id = %s"
    )
    user_id = login_user.id
    cursor.execute(query, (contact_name, key, phone, key, email, key, id))
    connection.commit()
    connection.close()
    
def new_contact_form(contact_name_entry, phone_entry, email_entry, view_frm, new_contact_frm, edit_contact_frm):
    contact_name = contact_name_entry.get()
    phone = phone_entry.get()
    email = email_entry.get()

    if not contact_name:
        messagebox.showerror("Error", "Contact name can not be empty.")
    else:
        save_contact_db(contact_name, phone, email)
        messagebox.showinfo("Correct", "New contact has been added.")
        switch_func(view_frm, new_contact_frm, edit_contact_frm, "newback")  

def update_contact_form(contact_name_entry, phone_entry, email_entry, id, view_frm, new_contact_frm, edit_contact_frm):
    contact_name = contact_name_entry.get()
    phone = phone_entry.get()
    email = email_entry.get()

    if not contact_name:
        messagebox.showerror("Error", "Contact name can not be empty.")
    else:
        update_contact_db(contact_name, phone, email, id)
        messagebox.showinfo("Correct", "Contact has been updated.")
        switch_func(view_frm, new_contact_frm, edit_contact_frm, "editback")  
        
def delete_contact(id ,view_frm, new_contact_frm, edit_contact_frm):
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = "DELETE FROM contacts WHERE id = %s"
    cursor.execute(query, (id,))
    connection.commit()
    cursor.close()
    connection.close()
    messagebox.showinfo("Correct", "Contact has been deleted.")
    switch_func(view_frm, new_contact_frm, edit_contact_frm, "editback") 
                
def set_edit_contact_frame(view_frm, new_contact_frm, edit_contact_frm, selected_contact):
    for widget in edit_contact_frm.winfo_children():
        widget.destroy()
        
    contact_name_label = tk.Label(edit_contact_frm, text="Contact Name:")
    contact_name_label.pack(pady=5)
    contact_name_entry = tk.Entry(edit_contact_frm)
    contact_name_entry.insert(0, selected_contact.name)
    contact_name_entry.pack(pady=5)
    contact_name_tip = tk.Label(
        edit_contact_frm, 
        text="", 
        fg="grey", 
        wraplength=200
    )
    contact_name_tip.pack(pady=5)
    contact_name_entry.bind(
        "<FocusOut>", 
        lambda event, 
        entry=contact_name_entry, tip=contact_name_tip: check_contactname_format(entry, tip)
    )

    phone_label = tk.Label(edit_contact_frm, text="Phone Number:")
    phone_label.pack(pady=5)
    phone_entry = tk.Entry(edit_contact_frm)
    phone_entry.insert(0, selected_contact.phone_number)
    phone_entry.pack(pady=5)
    
    email_label = tk.Label(edit_contact_frm, text="Email:")
    email_label.pack(pady=5)
    email_entry = tk.Entry(edit_contact_frm) 
    email_entry.insert(0, selected_contact.email)
    email_entry.pack(pady=5)
    
    save_button = tk.Button(edit_contact_frm, text="Update", command=lambda: update_contact_form(contact_name_entry, phone_entry, email_entry, selected_contact.id ,view_frm, new_contact_frm, edit_contact_frm))
    save_button.pack(pady=10)
    save_button = tk.Button(edit_contact_frm, text="Delete", command=lambda: delete_contact(selected_contact.id ,view_frm, new_contact_frm, edit_contact_frm))
    save_button.pack(pady=10)
    back_button = tk.Button(edit_contact_frm, text="Back", command=lambda: switch_func(view_frm, new_contact_frm, edit_contact_frm, "editback"))
    back_button.pack(pady=10)
               
def set_new_contact_frame(view_frm, new_contact_frm, edit_contact_frm):
    for widget in new_contact_frm.winfo_children():
        widget.destroy()
        
    contact_name_label = tk.Label(new_contact_frm, text="Contact Name:")
    contact_name_label.pack(pady=5)
    contact_name_entry = tk.Entry(new_contact_frm)
    contact_name_entry.pack(pady=5)
    contact_name_tip = tk.Label(
        new_contact_frm, 
        text="", 
        fg="grey", 
        wraplength=200
    )
    contact_name_tip.pack(pady=5)
    contact_name_entry.bind(
        "<FocusOut>", 
        lambda event, 
        entry=contact_name_entry, tip=contact_name_tip: check_contactname_format(entry, tip)
    )

    phone_label = tk.Label(new_contact_frm, text="Phone Number:")
    phone_label.pack(pady=5)
    phone_entry = tk.Entry(new_contact_frm)
    phone_entry.pack(pady=5)
    
    email_label = tk.Label(new_contact_frm, text="Email:")
    email_label.pack(pady=5)
    email_entry = tk.Entry(new_contact_frm) 
    email_entry.pack(pady=5)
    
    save_button = tk.Button(new_contact_frm, text="Save", command=lambda: new_contact_form(contact_name_entry, phone_entry, email_entry, view_frm, new_contact_frm, edit_contact_frm,))
    save_button.pack(pady=10)
    
    back_button = tk.Button(new_contact_frm, text="Back", command=lambda: switch_func(view_frm, new_contact_frm, edit_contact_frm, "newback"))
    back_button.pack(pady=10)

def on_treeview_select(event, tree, view_frm, new_contact_frm, edit_contact_frm):
    print ("tree select")
    selected_item = tree.selection()
    if selected_item:
        row_id = selected_item[0]
        print (row_id)
        for contact, contact_row_id in contact_row_mapping:
            if contact_row_id == row_id:
                print ("contact find")
                selected_contact = contact
                set_edit_contact_frame(view_frm, new_contact_frm, edit_contact_frm, selected_contact)
                switch_func(view_frm, new_contact_frm, edit_contact_frm, "edit")
                break
        
    
                
def set_viewfrm(view_frm, new_contact_frm, edit_contact_frm):
    for widget in view_frm.winfo_children():
        widget.destroy()
    
    tree = ttk.Treeview(view_frm, columns=("name", "phone", "email"), show="headings")
    tree.heading("name", text="Contact Name")
    tree.heading("phone", text="Phone Number")
    tree.heading("email", text="Email")
    tree.column("name", width=150)
    tree.column("phone", width=150)
    tree.column("email", width=150)
    tree.bind("<<TreeviewSelect>>", lambda event: on_treeview_select(event, tree, view_frm, new_contact_frm, edit_contact_frm))
    fill_treeview(tree)
        
    contacts_label = tk.Label(view_frm, text=str(len(contacts_list))+" contacts", font=CEStyle.title2_font)
    contacts_label.grid(row=0, column=0, columnspan=3, padx=10)
    
    search_entry = tk.Entry(view_frm)
    search_entry.grid(row=1, column=0, padx=5)
    
    search_button = tk.Button(view_frm, text="Search Contact", command=lambda: search_button_clicked(search_entry, tree, contacts_label))
    search_button.grid(row=1, column=1, padx=5)
    
    clear_button = tk.Button(view_frm, text="Clear Search", command=lambda: (fill_treeview(tree), search_entry.delete(0, tk.END), contacts_label.config(text=str(len(contacts_list))+" contacts")))
    clear_button.grid(row=1, column=2, padx=5)
    
    tree.grid(row=2, column=0, columnspan=3, padx=10)
    

def set_userpage():
    for widget in user_frm.winfo_children():
        widget.destroy()
        
    menu_frm = tk.Frame(user_frm, padx=10, pady=10)
    menu_frm.pack()
    
    title_label = tk.Label(menu_frm, text="Hello "+login_user.name+" !", font=CEStyle.title1_font, padx=10, pady=10)
    title_label.grid(row=0, column=0, columnspan=2, padx=10)
    
    view_frm = tk.Frame(user_frm, padx=10, pady=10)
    new_contact_frm = tk.Frame(user_frm, padx=10, pady=10)
    
    edit_contact_frm = tk.Frame(user_frm, padx=10, pady=10)
    
    set_viewfrm(view_frm, new_contact_frm, edit_contact_frm)
    view_frm.pack()
    
    add_contact_button = tk.Button(menu_frm, text="New Contact", command=lambda: switch_func(view_frm, new_contact_frm, edit_contact_frm, "new"))
    add_contact_button.grid(row=1, column=0, padx=10)
    
    logout_button = tk.Button(menu_frm, text="Log Out", command=lambda: switch_page(home_frm, user_frm))
    logout_button.grid(row=1, column=1, padx=10)      
  
                
def set_loginpage():
    for widget in login_frm.winfo_children():
        widget.destroy()
    
    username_label = tk.Label(login_frm, text="Username:")
    username_label.pack(pady=5)
    username_entry = tk.Entry(login_frm)
    username_entry.insert(0, "violetz")
    username_entry.pack(pady=5)
    username_tip = tk.Label(login_frm, text="")
    username_tip.pack(pady=5)
    username_entry.bind(
        "<FocusOut>", 
        lambda event, 
        entry=username_entry, tip=username_tip: login_username_format(entry, tip)
    )

    password_label = tk.Label(login_frm, text="Password:")
    password_label.pack(pady=5)
    password_entry = tk.Entry(login_frm, show="*")
    password_entry.insert(0, "Abc123@@")
    password_entry.pack(pady=5)
    password_tip = tk.Label(login_frm, text="")
    password_tip.pack(pady=5)
    password_entry.bind(
        "<FocusOut>", 
        lambda event, 
        entry=password_entry, tip=password_tip: login_password_format(entry, tip)
    )
    
    login_button = tk.Button(login_frm, text="Login", command=lambda: login_form(username_entry, password_entry))
    login_button.pack(pady=10)
    
    back_button = tk.Button(login_frm, text="Back", command=lambda: switch_page(home_frm, login_frm))
    back_button.pack(pady=10)


def set_registerpage():
    for widget in register_frm.winfo_children():
        widget.destroy()
        
    username_label = tk.Label(register_frm, text="Username:")
    username_label.pack(pady=5)
    username_entry = tk.Entry(register_frm)
    username_entry.pack(pady=5)
    username_tip = tk.Label(
        register_frm, 
        text="A valid username use only letters, numbers, or symbols (@, ., -, _), and have a length between 6 and 8 characters.", 
        fg="grey", 
        wraplength=200
    )
    username_tip.pack(pady=5)
    username_entry.bind(
        "<FocusOut>", 
        lambda event, 
        entry=username_entry, tip=username_tip: check_username_format(entry, tip)
    )

    password_label = tk.Label(register_frm, text="Password:")
    password_label.pack(pady=5)
    password_entry = tk.Entry(register_frm, show="*")
    password_entry.pack(pady=5)
    password_tip = tk.Label(
        register_frm, 
        text="A valid password must include at least one digit, one uppercase letter, one lowercase letter, one special character from (@, ., -, _), and have a length between 8 and 10 characters.", 
        fg="grey", 
        wraplength=200
    )
    password_tip.pack(pady=5)
    password_entry.bind(
        "<FocusOut>", 
        lambda event, 
        entry=password_entry, tip=password_tip: check_password_format(entry, tip)
    )

    confirm_password_label = tk.Label(register_frm, text="Confirm Password:")
    confirm_password_label.pack(pady=5)
    confirm_password_entry = tk.Entry(register_frm, show="*") 
    confirm_password_entry.pack(pady=5)
    confirm_password_tip = tk.Label(
        register_frm, 
        text="", 
        fg="grey", 
        wraplength=200
    )
    confirm_password_tip.pack(pady=5)
    confirm_password_entry.bind(
        "<FocusOut>", 
        lambda event, 
        pw_entry=password_entry, cf_entry=confirm_password_entry, pw_tip=password_tip, cf_tip=confirm_password_tip: confirm_password(pw_entry, cf_entry, pw_tip, cf_tip)
    )

    submit_button = tk.Button(register_frm, text="Submit", command=lambda: submit_form(username_entry, password_entry, confirm_password_entry, username_tip, password_tip, confirm_password_tip))
    submit_button.pack(pady=10)
    
    back_button = tk.Button(register_frm, text="Back", command=lambda: switch_page(home_frm, register_frm))
    back_button.pack(pady=10)
    
    
def set_homepage():
    logoimage_path = "contact.png" 
    logoimg = Image.open(logoimage_path)
    logoimg = logoimg.resize((150, 150))
    logoimg = ImageTk.PhotoImage(logoimg)
    logo_label = tk.Label(home_frm, image=logoimg, padx=5, pady=5)
    logo_label.pack(side="top")
    
    title_label = tk.Label(home_frm, text="Welcome to ContactEase.\nYour Personal Contact Manager.", font=CEStyle.title1_font, padx=10, pady=10)
    title_label.pack()
    
    login_button = tk.Button(home_frm, text="Login", font=CEStyle.button_font, padx=5, pady=5, command=lambda: switch_page(login_frm, home_frm))
    login_button.pack()
    
    register_button = tk.Button(home_frm, text="Register", font=CEStyle.button_font, padx=5, pady=5, command=lambda: switch_page(register_frm, home_frm))
    register_button.pack()

    
def on_click_outside(event):
    event.widget.focus_set()

       
def main(): 
    root.title('ContactEase')
    root.geometry("800x600")
    root.bind('<Button-1>', on_click_outside)
    
    set_homepage()
    set_loginpage()
    set_registerpage()
    
    home_frm.pack(side="top", fill="both", expand=True)
    
    root.mainloop()


def authenticate_login(username, password):
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = "SELECT `id` FROM `users` WHERE AES_DECRYPT(username, %s) = %s AND AES_DECRYPT(password, %s) = %s"
    cursor.execute(query, (key, username, key, hash_password(password)))
    results = cursor.fetchall()
    
    global login_user
    if len(results) != 0:
        user_id = results[0][0]
        login_user = User(username, user_id)
        return True
    
    return False 


def login_form(username_entry, password_entry):
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and Password can not be empty")
    elif authenticate_login(username, password):
        messagebox.showinfo("Correct", "Login successfully")
        switch_page(user_frm, login_frm)
    else:
        messagebox.showerror("Error", "Username and Password do not match")   


def login_username_format(entry, tip):
    if not entry.get():
        tip.config(
            text="Username cannot be empty.",
            fg="red"
        )
    else:
        tip.config(
            text="",
            fg="grey"
        )
        
        
def login_password_format(entry, tip):
    if not entry.get():
        tip.config(
            text="Password cannot be empty.",
            fg="red"
        )
    else:
        tip.config(
            text="",
            fg="grey"
        )


def hash_password(plain_password):
    sha256 = hashlib.sha256()
    sha256.update(plain_password.encode('utf-8'))
    hashed_password = sha256.hexdigest()
    return hashed_password
 
         
def save_user_db(username, password):
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = "INSERT INTO `users` (username, password) VALUES (AES_ENCRYPT(%s, %s), AES_ENCRYPT(%s, %s))"
    cursor.execute(query, (username, key, hash_password(password), key))
    connection.commit()
    connection.close()


def submit_form(username_entry, password_entry, confirm_password_entry, username_tip, password_tip, confirm_password_tip):
    username = username_entry.get()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()

    if username_tip.cget("text")!="Username is valid." or password_tip.cget("text")!="Password is valid.":
        messagebox.showerror("Error", "Please enter valid username and password")
    elif password != confirm_password:
        messagebox.showerror("Error", "Passwords don't match")
    else:
        save_user_db(username, password)
        messagebox.showinfo("Correct", "Registered successfully")
        switch_page(home_frm, register_frm)
     
  
def username_avaliable(username_to_check):
    connection = mysql.connector.connect(host=db_host, port=db_port, user=db_user, password=db_password, database=db_database)
    cursor = connection.cursor()
    query = "SELECT * FROM `users` WHERE AES_DECRYPT(username, %s) = %s"
    cursor.execute(query, (key, username_to_check))
    results = cursor.fetchall()
    return len(results) == 0


def check_username_format(entry, tip):
    username_regex = r"^[a-zA-Z0-9@._-]{6,8}$"
    username = entry.get()
    if not username:
        tip.config(
            text="Username cannot be empty. A valid username use only letters, numbers, or symbols (@, ., -, _), and have a length between 6 and 8 characters.",
            fg="red"
        )
    elif not re.match(username_regex, username):
        tip.config(
            text="Invalid username. A valid username use only letters, numbers, or symbols (@, ., -, _), and have a length between 6 and 8 characters.",
            fg="red"
        )
    elif not username_avaliable(username):
        tip.config(
            text="This username is already in use. A valid username use only letters, numbers, or symbols (@, ., -, _), and have a length between 6 and 8 characters.",
            fg="red"
        )
    else:
        tip.config(
            text="Username is valid.",
            fg="green"
        )
        
def confirm_password(pw_entry, cf_entry, pw_tip, cf_tip):
    password = pw_entry.get()
    cf_password = cf_entry.get()
    
    if pw_tip.cget("text")!="Password is valid.":
        cf_tip.config(
            text="Please enter a valid password.",
            fg="red"
        )
    elif password==cf_password:
        cf_tip.config(
            text="Password has been comfirmed.",
            fg="green"
        )
    else:
        cf_tip.config(
            text="Passwords do not match.",
            fg="red"
        )

        
def check_password_format(entry, tip):
    password_regex = r"^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[@._-]).{8,10}$"  
    password = entry.get() 
    if not password:
        tip.config(
            text="Password cannot be empty. A valid password must include at least one digit, one uppercase letter, one lowercase letter, one special character from (@, ., -, _), and have a length between 8 and 10 characters.",
            fg="red"
        )
    elif not re.match(password_regex, password):
        tip.config(
            text="Invalid password. A valid password must include at least one digit, one uppercase letter, one lowercase letter, one special character from (@, ., -, _), and have a length between 8 and 10 characters.",
            fg="red"
        )
    else:
        tip.config(
            text="Password is valid.",
            fg="green"
        )

           
if __name__ == "__main__":
    main()    
