from tkinter import *
from tkinter import ttk
from tkinter.ttk import Combobox
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import askopenfilenames
from tkinter.filedialog import askdirectory
from tkinter.filedialog import asksaveasfilename
import tkinter.scrolledtext as scrolledtext
from base64 import b64encode, b64decode
from promptuser import pufiles, pufile, pudir, pusavefile

from rsaf import *
"""
gen_key(length=4096)
write_key(key, fn="private_key.pem")
print_key(key)
read_key(fn="private_key.pem")
der_pub(key)
"""

def gen_priv():
    global left_key
    left_key = gen_key()
    left_txt.delete(1.0, END)
    left_txt.insert(END, fromobj(left_key))
def load_priv():
    global left_key
    left_key = read_key(pufile())
    left_txt.delete(1.0, END)
    left_txt.insert(END, fromobj(left_key))
def store_priv():
    global left_key
    #print(left_key is None)
    if not write_key(left_key, pusavefile()):
        store_priv_button.config(background="pink")
    else:
        store_priv_button.config(background="lime")
def gen_pub():
    global right_key
    global left_key
    right_key = der_pub(left_key)
    if right_key is None:
        gen_pub_button.config(background="pink")
    else:
        gen_pub_button.config(background="lime")
    right_txt.delete(1.0, END)
    right_txt.insert(END, fromobj(right_key))
def load_pub():
    global right_key
    global left_key
    right_key = read_key(pufile())
    right_txt.delete(1.0, END)
    right_txt.insert(END, fromobj(right_key))
def store_pub():
    global right_key
    if not write_key(right_key, pusavefile()):
        store_pub_button.config(background="pink")
    else:
        store_pub_button.config(background="lime")

def enc():
    c = encrypt_rsa(left_res.get("1.0", "end-1c"), right_key)
    if c is None:
        enc_button.config(background="pink")
        return
    else:
        enc_button.config(background="lime")
    
    right_res.delete(1.0, END)
    right_res.insert(END, c)
    

def dec():
    p = decrypt_rsa(right_res.get("1.0", "end-1c"), left_key)
    if p is None:
        dec_button.config(background="pink")
        return
    else:
        dec_button.config(background="lime")
    left_res.delete(1.0, END)
    left_res.insert(END, p)

def update_key_l():
    global left_key
    raw_left = left_txt.get("1.0", "end-1c")
    left_key = toobj(raw_left)

def update_key_r():
    global right_key
    raw_right = right_txt.get("1.0", "end-1c")
    right_key = toobj(raw_right)

if __name__ == '__main__':
    #multiprocessing.freeze_support()
    root=Tk()

    class Window(Frame):
        '''
        THE GUI
        '''
        def __init__(self, master=None):
            
            Frame.__init__(self, master)
            self.master = master
            self.pack(fill=BOTH, expand=1)

    keybuttonrow = Frame(root)
    keybuttonrow.pack(side=TOP, fill=X, padx=5, pady=5)
    gen_priv_button = Button(keybuttonrow, text="Generate Private Key", command=gen_priv)
    gen_priv_button.pack(side=LEFT, padx=10, pady=10)
    load_priv_button = Button(keybuttonrow, text="Load Private Key", command=load_priv)
    load_priv_button.pack(side=LEFT, padx=10, pady=10)
    store_priv_button = Button(keybuttonrow, text="Store Private Key", command=store_priv)
    store_priv_button.pack(side=LEFT, padx=10, pady=10)
    updatel_button = Button(keybuttonrow, text="Update Pasted Key", command=update_key_l)
    updatel_button.pack(side=LEFT, padx=10, pady=10)
    

    gen_pub_button = Button(keybuttonrow, text="Generate Public Key", command=gen_pub)
    gen_pub_button.pack(side=RIGHT, padx=10, pady=10)
    load_pub_button = Button(keybuttonrow, text="Load Public Key", command=load_pub)
    load_pub_button.pack(side=RIGHT, padx=10, pady=10)
    store_pub_button = Button(keybuttonrow, text="Store Public Key", command=store_pub)
    store_pub_button.pack(side=RIGHT, padx=10, pady=10)
    updater_button = Button(keybuttonrow, text="Update Pasted Key", command=update_key_r)
    updater_button.pack(side=RIGHT, padx=10, pady=10)
    

    keyrow = Frame(root)
    keyrow.pack(side=TOP, fill=X, padx=5, pady=5)

    left_key = None
    left_txt_var = StringVar()
    left_txt_var.set("test0")
    left_txt = scrolledtext.ScrolledText(keyrow, undo=True, height=10, width=50)
    left_txt.insert(END, left_txt_var.get())
    left_txt.config(state="normal")
    left_txt.pack(side=LEFT, fill=X, padx=5, pady=5)
    
    right_key = None
    right_txt_var = StringVar()
    right_txt_var.set("test")
    right_txt = scrolledtext.ScrolledText(keyrow, undo=True, height=10, width=50)
    right_txt.insert(END, right_txt_var.get())
    right_txt.config(state="normal")
    right_txt.pack(side=RIGHT, fill=X, padx=5, pady=5)
    
    
    approw = Frame(root)
    approw.pack(side=TOP, fill=X, padx=5, pady=5)
    enc_button = Button(approw, text="-- Encrypt with Public Key -->", command=enc)
    enc_button.pack(side=LEFT, padx=100, pady=10)
    dec_button = Button(approw, text="<-- Decrypt with Private Key --", command=dec)
    dec_button.pack(side=RIGHT, padx=100, pady=10)

    resultrow = Frame(root)
    resultrow.pack(side=TOP, fill=X, padx=5, pady=5)

    left_res_var = StringVar()
    left_res_var.set("res")
    left_res = scrolledtext.ScrolledText(resultrow, undo=True, height=20, width=50)
    left_res.insert(END, left_res_var.get())
    left_res.config(state="normal")
    left_res.pack(side=LEFT, fill=X, padx=5, pady=5)
    
    right_res_var = StringVar()
    right_res_var.set("res")
    right_res = scrolledtext.ScrolledText(resultrow, undo=True, height=20, width=50)
    right_res.insert(END, right_res_var.get())
    right_res.config(state="normal")
    right_res.pack(side=RIGHT, fill=X, padx=5, pady=5)
  



    #GUI Window Title and Size:
    root.wm_title("Crypt Client")
    root.geometry(str(int(1050))+"x"+str(int(700)))

    root.mainloop()