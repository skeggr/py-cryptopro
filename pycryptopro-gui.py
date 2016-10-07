from pycryptopro.utils import Certmgr, ShellCommand
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import re

class Csptest(ShellCommand):
    """
    Обертка над утилитой csptest, входящей в состав Крипто-Про CSP (для UNIX-платформ).
    """

    def __init__(self, binary='/opt/cprocsp/bin/amd64/csptest'):
        self.binary = binary

    def enum(self):
        stdout = self.run_command(self.binary,'-keyset', '-enum_cont', '-verifyc', '-fq')
        conts = [line for line in stdout.split(b'\n') if line.startswith(b'\\\\.')]
        return conts


class SecondaryForm(tk.Toplevel):
    def create_shared_widgets(self):
        self.geometry('540x300+330+330')
        self.cont_lbl = tk.Label(self, text='Доступные контейнеры:')
        self.cont_lbl.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        self.cont_list = tk.Listbox(self, height=10, width=65, selectmode=tk.SINGLE)
        self.cont_list.grid(row=1, column=0, columnspan=4, padx=5, sticky='w')

    def create_export_widgets(self):
        self.file_lbl = tk.Label(self, text='Файл для экспорта:')
        self.file_lbl.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        self.file_entry = tk.Entry(self, width=55)
        self.file_entry.grid(row=3, column=0, columnspan=4, padx=5, sticky='w')
        self.file_browse_btn = tk.Button(self, text='Обзор')
        self.file_browse_btn.grid(row=3, column=3, padx=5, sticky='e')
        self.export_btn = tk.Button(self, text='Экспортировать')
        self.export_btn.grid(row=4, column=3, padx=5, pady=15, sticky='e')
        self.cancel_btn = tk.Button(self, text='Отмена', command=lambda: self.destroy())
        self.cancel_btn.grid(row=4, column=0, padx=5, pady=15, sticky='w')


class App(tk.Tk):
    def create_widgets(self):
        self.nb = ttk.Notebook(self)
        self.page1 = ttk.Frame(self.nb)
        self.page2 = ttk.Frame(self.nb)
        self.nb.add(self.page1, text='Сертификаты')
        self.nb.add(self.page2, text='Считыватели')
        self.nb.pack(expand=1, fill='both')
        self.cert_store_lbl = tk.Label(self.page1, text='Хранилище сертификатов:')
        self.cert_store_lbl.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        self.cert_store_combo = ttk.Combobox(self.page1, values=['uMy', 'uRoot'], width=7)
        self.cert_store_combo.grid(row=1, column=2, sticky='e', columnspan=2,padx=10)
        self.cert_store_combo.bind('<<ComboboxSelected>>', self.get_certs)
        self.cert_list = tk.Listbox(self.page1, height=7, width=48, selectmode=tk.SINGLE)
        self.cert_list.grid(row=2, column=0, columnspan=4, padx=5, sticky='w')
        self.cert_list.bind('<Double-1>', self.show_cert_prop)
        self.cert_list.bind('<<ListboxSelect>>', self.show_cert_prop)
        self.cert_prop_text = tk.Text(self.page1, state=tk.DISABLED, height=14, width=55)
        self.cert_prop_text.grid(row=3, column=0, columnspan=4, pady=5, padx=5, sticky='w')
        self.cert_export_btn = tk.Button(self.page1, text='Установить...')
        self.cert_export_btn.grid(row=4, column=0, pady=5, padx=5, sticky='w')
        self.cert_export_btn = tk.Button(self.page1, text='Экспортировать...', command=self.export_cert)
        self.cert_export_btn.grid(row=4, column=1, pady=5, padx=5, sticky='w')
        self.cert_export_btn = tk.Button(self.page1, text='Удалить...')
        self.cert_export_btn.grid(row=4, column=2, pady=5, padx=5, sticky='w')
        self.cert_export_btn = tk.Button(self.page1, text='Экспортировать из контейнера...', command=self.export_from_cont)
        self.cert_export_btn.grid(row=5, column=0, columnspan=3, pady=5, padx=5, sticky='w')


    def export_from_cont(self):
        toplvl = SecondaryForm(self)
        toplvl.create_shared_widgets()
        toplvl.create_export_widgets()
        for cont in self.enum_conts():
            toplvl.cont_list.insert(tk.END, cont)


    def enum_conts(self):
        conts = Csptest().enum()
        if conts:
            return conts
        else:
            return []

    def delete_cert(self):
        pass


    def export_cert(self):
        file = filedialog.asksaveasfilename()
        cmd = Certmgr()
        print(cmd.run_command('-export', '-store', self.cert_store_combo.get(), '-thumbprint', next(cert.thumbprint for cert in self.certs if cert.subject.as_dict()['CN'] == self.cert_list.selection_get()), '-dest', file))


    def get_certs(self, event):
        self.cert_prop_text.configure(state=tk.NORMAL)
        self.cert_prop_text.delete(1.0, tk.END)
        self.cert_prop_text.configure(state=tk.DISABLED)
        certmgr = Certmgr()
        self.cert_list.delete(first=0, last=tk.END)
        self.certs = certmgr.list(store=self.cert_store_combo.get(), limit=100)
        for cert in self.certs:
            self.cert_list.insert(tk.END, cert.subject.as_dict()['CN'])

    def formatting_and_output(self, **kwargs):
        for elem in kwargs.keys():
            self.cert_prop_text.insert(tk.END, '{0}:\t\t{1}\n'.format(elem, kwargs[elem]))

    #TODO
    #Decorator for unblock and clear textbox

    def show_cert_prop(self, event):
        #if self.cert_list.selection_get():
        #    self.prop_frame = tk.Toplevel(self)
        for cert in self.certs:
            if cert.subject.as_dict()['CN'] == self.cert_list.selection_get():
                self.cert_prop_text.configure(state=tk.NORMAL)
                self.cert_prop_text.delete(1.0, tk.END)
                person = cert.subject.as_dict()
                props = ({'Имя': person['CN']}, {'Подразделение': person['OU']}, {'Организация': person['O']}, {'E-mail': person['E']}, {'Годен до': cert.valid_to}, {'Номер': cert.serial}, {'Издатель': cert.issuer})
                for elem in props:
                    self.formatting_and_output(**elem)
                self.cert_prop_text.configure(state=tk.DISABLED)

if __name__ == '__main__':
    root = App()
    root.create_widgets()
    root.geometry('400x550+300+300')
    root.mainloop()