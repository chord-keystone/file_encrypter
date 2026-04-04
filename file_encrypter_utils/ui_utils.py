# general
import pathlib
from typing import Iterable
from os import startfile
from file_encrypter_utils.utils import file_entry_manager

# UI things
import ttkbootstrap as ttk
from ttkbootstrap.dialogs import *
from ttkbootstrap.dialogs.message import *
from tkinter.scrolledtext import ScrolledText
from tkinter.filedialog import askdirectory
from itertools import cycle
from PIL import Image, ImageTk, ImageSequence

class ListedDialog(Dialog):

    def __init__(
        self,
        message_beforelist,
        list_message,
        message_afterlist,
        title=" ",
        buttons=None,
        command=None,
        width=50,
        parent=None,
        alert=False,
        default=None,
        padding=(20, 20),
        icon=None,
        **kwargs,
    ):
        super().__init__(parent, title, alert)
        self._msg_before = message_beforelist
        self._msg_after = message_afterlist
        self._list_msg = list_message
        self._command = command
        self._width = width
        self._alert = alert
        self._default = default
        self._padding = padding
        self._icon = icon
        self._localize = kwargs.get("localize")

        if buttons is None:
            self._buttons = [
                f"{MessageCatalog.translate('Cancel')}",
                f"{MessageCatalog.translate('OK')}",
            ]
        else:
            self._buttons = buttons

    def create_body(self, master):
        """Overrides the parent method; adds the message section."""
        container = ttk.Frame(master, padding=self._padding)
        if self._icon:
            try:
                # assume this is image data
                self._img = ttk.PhotoImage(data=self._icon)
                icon_lbl = ttk.Label(container, image=self._img)
                icon_lbl.pack(side=LEFT, anchor=N, padx=(0, 5))
            except:
                try:
                    # assume this is a file path
                    self._img = ttk.PhotoImage(file=self._icon)
                    icon_lbl = ttk.Label(container, image=self._img)
                    icon_lbl.pack(side=LEFT, anchor=N, padx=(0, 5))
                except:
                    # icon is neither data nor a valid file path
                    print("MessageDialog icon is invalid")

        if self._msg_before:
            for msg in self._msg_before.split("\n"):
                message = "\n".join(textwrap.wrap(msg, width=self._width))
                message_label = ttk.Label(container, text=message)
                message_label.pack(pady=(0, 3), fill=X, anchor=N)

        if self._list_msg:
            scrollist = ScrolledText(master=container, wrap=WORD, width=self._width, height=10)
            for ele in self._list_msg:
                scrollist.insert(INSERT, str(ele) + "\n")

            scrollist.configure(state="disabled")
            scrollist.pack(pady=(0, 3), fill=X, anchor=N)

        if self._msg_after:
            for msg in self._msg_after.split("\n"):
                message = "\n".join(textwrap.wrap(msg, width=self._width))
                message_label = ttk.Label(container, text=message)
                message_label.pack(pady=(0, 3), fill=X, anchor=N)

        container.pack(fill=X, expand=True)

    def create_buttonbox(self, master):
        """Overrides the parent method; adds the message buttonbox"""
        frame = ttk.Frame(master, padding=(5, 5))

        button_list = []

        for i, button in enumerate(self._buttons[::-1]):
            cnf = button.split(":")
            text = cnf[0]

            is_default = False
            if self._default is not None and text == self._default:
                is_default = True
            elif self._default is None and i == 0:
                is_default = True

            if len(cnf) == 2:
                bootstyle = cnf[1]
            elif is_default:
                bootstyle = 'primary'
            else:
                bootstyle = 'secondary'

            if self._localize == True:
                text = MessageCatalog.translate(text)

            btn = ttk.Button(frame, bootstyle=bootstyle, text=text)
            btn.configure(command=lambda b=btn: self.on_button_press(b))
            btn.pack(padx=2, side=RIGHT)
            btn.lower()  # set focus traversal left-to-right
            button_list.append(btn)

            if is_default:
                self._initial_focus = btn

            # bind default button to return key press and set focus
            btn.bind("<Return>", lambda _, b=btn: b.invoke())
            btn.bind("<KP_Enter>", lambda _, b=btn: b.invoke())

        for index, btn in enumerate(button_list):
            if index > 0:
                nbtn = button_list[index - 1]
                btn.bind('<Right>', lambda _, b=nbtn:b.focus_set())
            if index < len(button_list) - 1:
                nbtn = button_list[index + 1]
                btn.bind('<Left>', lambda _, b=nbtn:b.focus_set())

        ttk.Separator(self._toplevel).pack(fill=X)
        frame.pack(side=BOTTOM, fill=X, anchor=S)

        if not self._initial_focus:
            self._initial_focus = button_list[0]

    def on_button_press(self, button):
        """Save result, destroy the toplevel, and execute command."""
        self._result = button["text"]
        command = self._command
        if command is not None:
            command()
        self._toplevel.after_idle(self._toplevel.destroy)

    def show(self, position=None):
        """Create and display the popup messagebox."""
        super().show(position)

class ListMessageDialog:

    @staticmethod
    def show_info(message_before:str="", list_msg:list[str] = [""], message_after:str="", title=" ", parent=None, alert=False, **kwargs):

        dlg = ListedDialog(
            message_beforelist=message_before,
            message_afterlist=message_after,
            list_message=list_msg,
            title=title,
            alert=alert,
            parent=parent,
            buttons=["OK:primary"],
            icon=Icon.info,
            localize=True,
            **kwargs
        )
        if "position" in kwargs:
            position = kwargs.pop("position")
        else:
            position = None
        dlg.show(position)

    @staticmethod
    def show_warning(message_before:str="", list_msg:list[str] = [""], message_after:str="", title=" ", parent=None, alert=False, **kwargs):

        dlg = ListedDialog(
            message_beforelist=message_before,
            message_afterlist=message_after,
            list_message=list_msg,
            title=title,
            alert=alert,
            parent=parent,
            buttons=["OK:primary"],
            icon=Icon.warning,
            localize=True,
            **kwargs
        )
        if "position" in kwargs:
            position = kwargs.pop("position")
        else:
            position = None
        dlg.show(position)

    @staticmethod
    def show_error(message_before:str="", list_msg:list[str] = [""], message_after:str="", title=" ", parent=None, alert=False, **kwargs):

        dlg = ListedDialog(
            message_beforelist=message_before,
            message_afterlist=message_after,
            list_message=list_msg,
            title=title,
            alert=alert,
            parent=parent,
            buttons=["OK:primary"],
            icon=Icon.error,
            localize=True,
            **kwargs
        )
        if "position" in kwargs:
            position = kwargs.pop("position")
        else:
            position = None
        dlg.show(position)

class PasswordQueryDialog(QueryDialog):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def create_body(self, master):
        """Overrides the parent method; adds the message and input
            section."""
        
        frame = ttk.Frame(master, padding=self._padding)
        if len(self._prompt.split("\n")) == 2:
            self.entry = []
            for p in self._prompt.split("\n"):
                prompt = "\n".join(textwrap.wrap(p, width=self._width))
                prompt_label = ttk.Label(frame, text=prompt)
                prompt_label.pack(pady=(0, 5), fill=X, anchor=N)
                if self._items is None or len(self._items) == 0:
                    self.entry.append(ttk.Entry(master=frame))
                else:
                    self.entry.append(ttk.Combobox(master=frame, values=self._items))
                    self.entry[-1].bind('<KeyRelease>', self.on_filter_list)

                self.entry[-1].insert(END, self._initialvalue)
                self.entry[-1].pack(pady=(0, 5), fill=X)
                self.entry[-1].bind("<Return>", self.on_submit)
                self.entry[-1].bind("<KP_Enter>", self.on_submit)
                self.entry[-1].bind("<Escape>", self.on_cancel)

            self._pwlabel = ttk.Label(frame, text="")
            self._pwlabel.pack(pady=(0, 5), fill=X, anchor=N)

        else:
            raise ValueError("Prompt must have exactly two lines for password and confirmation.")
            
        frame.pack(fill=X, expand=True)
        self._initial_focus = self.entry[0]

    def validate(self):
        if self.entry[0].get() != self.entry[1].get():
            self._pwlabel.config(text="Passwords do not match.", foreground="red")
            self.entry[0].config(foreground="red")
            self.entry[1].config(foreground="red")
            return False
        elif len(self.entry[0].get()) < 10:
            self._pwlabel.config(text="Password must be at least 10 characters.", foreground="red")
            self.entry[0].config(foreground="red")
            return False
        else:
            return True

    def create_buttonbox(self, master):
        """Overrides the parent method; adds the message buttonbox"""
        frame = ttk.Frame(master, padding=(5, 10))

        submit = ttk.Button(
            master=frame,
            bootstyle="primary",
            text=MessageCatalog.translate("Submit"),
            command=self.on_submit,
        )
        submit.pack(padx=5, side=RIGHT)
        submit.lower()  # set focus traversal left-to-right

        # no cancel buttun here

        ttk.Separator(self._toplevel).pack(fill=X)
        frame.pack(side=BOTTOM, fill=X, anchor=S)

class ButtonOptionsDialog(Dialog):
    """A modal dialog class that displays the input items as buttons, returning the
    index of the selected button from the input Iterable.
    """

    def __init__(
        self,
        prompt:str,
        items:Iterable[str],
        title=" ",
        initialvalue="",
        width=65,
        buttonwidth=20,
        padding=(20, 20),
        parent=None,
    ):
        """
        Parameters:

            prompt (iterable[str]):
                A list of strings that will be displayed as buttons.

            title (str):
                The string displayed as the title of the message box.
                This option is ignored on Mac OS X, where platform
                guidelines forbid the use of a title on this kind of
                dialog.

            width (int):
                The maximum number of characters per line in the
                message. If the text stretches beyond the limit, the
                line will break at the word.

            parent (Widget):
                Makes the window the logical parent of the message box.
                The messagebox is displayed on top of its parent
                window.

            padding (Union[int, Tuple[int]]):
                The amount of space between the border and the widget
                contents.
        """
        super().__init__(parent, title)
        self._prompt = prompt
        self._items = items
        self._initialvalue = initialvalue
        self._buttonwidth = buttonwidth
        self._width = width
        self._padding = padding
        self._result = None

    def create_body(self, master):
        """Overrides the parent method; adds the button."""
        frame = ttk.Frame(master, padding=self._padding)
        if self._prompt:
            prompt = "\n".join(textwrap.wrap(self._prompt, 
                                            width=self._width,
                                            replace_whitespace=False)
                                            )
            prompt = textwrap.indent(prompt, prefix=" "*4, predicate = lambda line: line.startswith("&")).replace("&", "")
            prompt_label = ttk.Label(frame, text=prompt)
            prompt_label.pack(pady=(0, 10), fill=X, anchor=N, expand=True)

        if self._items:
            buts = []
            for ii, p in enumerate(self._items):
                prompt = "\n".join(textwrap.wrap(p, width=self._buttonwidth))
                buts.append(ttk.Button(frame, text=prompt, command=lambda id=ii: self.on_submit(id)))
                buts[-1].pack(side=LEFT, fill=BOTH, expand=True)
    
        frame.pack(fill=X, expand=True)
        self._initial_focus = buts[0]
        ttk.Separator(self._toplevel).pack(fill=X)

    def create_buttonbox(self, master):
        pass

    def on_submit(self, but_id, *_):
        """Save result, destroy the toplevel, and apply any post-hoc
        data manipulations."""
        self._result = but_id
        self._toplevel.destroy()

class AnimatedGif(ttk.Frame):

    def __init__(self, master, file_path, text_input=None):
        super().__init__(master, width=300, height=200)

        # open the GIF and create a cycle iterator
        with Image.open(file_path) as im:
            # create a sequence
            sequence = ImageSequence.Iterator(im)
            images = [ImageTk.PhotoImage(s) for s in sequence]
            self.image_cycle = cycle(images)

            # length of each frame
            self.framerate = im.info["duration"]

        self.img_container = ttk.Label(self, image=next(self.image_cycle))
        self.img_container.grid(row=0, column=0, sticky='ew')

        if text_input is not None:
            ttk.Label(self, text=text_input).grid(row=1, column=0, sticky='w')

        self.after(self.framerate, self.next_frame)

    def next_frame(self):
        """Update the image for each frame"""
        self.img_container.configure(image=next(self.image_cycle))
        self.after(self.framerate, self.next_frame)

class FileView(ttk.Toplevel, object):
    
    _instance = None
    _already_init = False
    file_list_handle:file_entry_manager

    # singleton
    def __new__(cls, *args, **kwargs):

        if cls._instance is None or not cls._instance.winfo_exists():
            cls._instance = super(FileView, cls).__new__(cls)
        else:
            cls._instance.lift()
            cls._instance.focus()
        
        return cls._instance

    def __init__(self, master=None, flist:file_entry_manager=None, run_when_done=None):

        if self._already_init:
            return
        else:
            self._already_init = True

        if flist is None:
            ValueError("Missing required argument flist")

        self.event = run_when_done

        ttk.Toplevel.__init__(self, master)
        self.title("File List")
        self.geometry("800x500")
        self.file_list_handle = flist
        
        self.tv = ttk.Treeview(master=self, selectmode="browse", style="secondary")
        yscroll = ttk.Scrollbar(master=self, orient="vertical", command=self.tv.yview)
        xscroll = ttk.Scrollbar(master=self, orient='horizontal', command=self.tv.xview)
        self.tv.config(xscroll=xscroll.set, yscroll=yscroll.set)
        self.tv.heading("#0", text="Active Files", anchor="w")

        self.init_base_entries()

        adddirbutton = ttk.Button(master=self, text="Add Folder", command=self.dir_add, bootstyle="LIGHT")
        rmbutton = ttk.Button(master=self, text="Remove", command=self.remove, bootstyle="DANGER")
        okbutton = ttk.Button(master=self, text="OK", command=self.destroy, bootstyle="LIGHT")
        openbutton = ttk.Button(master=self, text="Open", command=self.open, bootstyle="SECONDARY")
        self.tv.bind("<Double-r>", self.open)

        self.grid()
        self.tv.grid(row=0, column=0, sticky='nsew', columnspan=4)
        xscroll.grid(row=1, column=0, sticky='ew')
        yscroll.grid(row=0, column=4, sticky='ns')

        openbutton.grid(row=2, column=0, padx=5, pady=5, sticky = 'w')
        adddirbutton.grid(row=2, column=2, padx=5, pady=5)
        rmbutton.grid(row=2, column=3, padx=5, pady=5)
        okbutton.grid(row=2, column=4, padx=5, pady=5)
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def open(self) -> None:
        selected = self.tv.selection()
        item_text = pathlib.Path(self.tv.item(selected)["text"])

        while not item_text.exists():
            selected = self.tv.item(selected)["tags"][0]
            parent = pathlib.Path(self.tv.item(selected)["text"])
            item_text = parent / item_text

        startfile(item_text)
        
    def destroy(self) -> any:
        if self.event is not None: self.event()
        self._already_init = False
        self._instance = None
        super().destroy()

    def init_base_entries(self) -> None:

        # remove anything in the body
        existing_items = self.tv.get_children()
        self.tv.delete(*existing_items)

        # add in the contents
        for item in self.file_list_handle.base_entries:
            inserted = self.tv.insert("", "end", text=item, open=True)
            if item.is_dir():
                self.tree_add(inserted, item)

    def tree_add(self, item:pathlib.Path, parent:pathlib.Path) -> None:

        for subitem in parent.iterdir():
            this_inserted = self.tv.insert(item, 'end', text=subitem, open=False, tags=item)
            if subitem.is_dir():
                self.tree_add(this_inserted, subitem)
                                
    def dir_add(self):
        
        get_dir = askdirectory()
        if get_dir:
            try:
                self.file_list_handle.add_item(pathlib.Path(get_dir))
            except Exception as e:
                if hasattr(e, "full_message"):
                    ListMessageDialog.show_error(
                        e.full_message.before,
                        e.full_message.msglist,
                        e.full_message.after
                    )
                else:
                    Messagebox.show_error(f"Error: {e}")
                return
        
        self.init_base_entries()
        self.focus()

    def remove(self):

        selection = self.tv.selection()
        text_selection = pathlib.Path(self.tv.item(selection)["text"])
        if selection:
            self.file_list_handle.remove_item(text_selection)
        
        self.init_base_entries()

def main():
    pass

if __name__ == "__main__":
    main()