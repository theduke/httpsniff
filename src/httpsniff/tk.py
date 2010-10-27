'''
Created on Oct 26, 2010

@author: theduke
'''

from Tkinter import *
from httpsniff import *

from operator import itemgetter
import tkMessageBox

class Application(object):
    '''
    classdocs
    '''
    
    tk = None
    controlWidget = None
    interfaceWidget = None
    toggleWidget = None
    contentWidget = None
    listWidget = None
    
    # {host+path: count}
    paths = {}
    
    sniffer = None
    snifferActive = False
    snifferConf = {'interface': None}
    
    hideStuff = None

    def __init__(self):
        self.sniffer = Sniffer()
        self.sniffer.newRequestCallback = self.onNewRequest
    
    def build(self):
        tk = Tk()
        
        tk.title('HTTP Sniff')
        
        root = Frame(tk, width=1000)
        root.pack()
        
        control = Frame(root, width=1000)
        control.pack()
        
        interface = Text(control, width=15, height=1)
        self.interfaceWidget = interface
        interface.pack(side=LEFT)
        
        self.toggleWidget = Button(control, text='Start Sniffing', command=self.onClick)
        self.toggleWidget.pack(side=LEFT)
        
        Button(control, text='Write to File', command=self.writeToFile).pack(side=LEFT)
        
        
        self.hideStuff = BooleanVar()
        self.hideStuff.set(True)
        
        hideStuff = Checkbutton(control, text="Hide images/javascript", variable=self.hideStuff)
        hideStuff.pack(side=LEFT)
        
        content = Frame(root, width=1000)
        
        scrollbar = Scrollbar(content)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        list = Listbox(content, width=120, height=30, yscrollcommand=scrollbar.set)
        list.pack(side=LEFT)
        
        scrollbar.config(command=list.yview)
        
        self.listWidget = list
        
        content.pack()
        
        tk.after(500, self.onTick)
        
        self.tk = tk
        tk.mainloop()
    
    def onClick(self):
        if self.snifferActive:
            self.snifferActive = False
            self.toggleWidget.configure(text='Start Sniffing')
        else:
            self.start()
            self.toggleWidget.configure(text='Stop Sniffing')
            
    def onQuit(self):
        if self.snifferActive:
            self.sniffer.stop() 
            
    def start(self):
        interface = self.interfaceWidget.get(1.0, END)
        interface = str(interface).replace('\n', '')
        
        self.snifferActive = True
        self.sniffer.prepare(interface)
        self.runSniffer()
    
    def runSniffer(self):
        self.sniffer.run(True, 50)
    
    def onTick(self):
        if self.snifferActive:
            self.sniffer.run(True, 50)
        
        self.tk.after(500, self.onTick)
        
    def onNewRequest(self, data):
        host, path, ip = data
        
        key = host + path
        if not key in self.paths:
            self.addPath(host, path)
        
        self.paths[key] += 1
        
        self.drawList()
            
    def addPath(self, host, path):
        self.paths[host+path] = 0
        
    def filter(self, data):
        newData = {}
        
        files = re.compile('\.(gif|jpeg|jpg|png|js|css|swf)(\?.*)?$')
        
        for k, v in data.items():
            if not files.search(k):
                newData[k] = v
        
        return newData
    
    def drawList(self):
                
        if self.hideStuff.get():
            data = self.filter(self.paths)
        else:
            data = self.paths.copy()
        
        data = sorted(data.iteritems(), key=itemgetter(1), reverse=True)
        
        self.listWidget.delete(0, END)
        
        for path, count in data:
            txt = path + '(' + str(count) + ')'
            self.listWidget.insert(END, txt)

        
    def writeToFile(self):
        dg = FileExportDialog(self.tk, self.sniffer.data)
        
        self.tk.wait_window(dg.window)
        
        
class FileExportDialog:
    window = None
    pathWidget = None
    
    data = None
    
    def __init__(self, parent, data):
        self.data = data
        
        w = Toplevel(parent)
        self.window = w
        
        f1 = Frame(w)
        f1.pack()
        
        Label(f1, text='File Path').pack(side=LEFT)
        
        path = Text(f1, width=30, height=1)
        self.pathWidget = path
        path.pack(side=LEFT)
        
        Button(w, text='Save to File', command=self.onClick).pack(side=TOP)
    
    def onClick(self):
        path = str(self.pathWidget.get(1.0, END)).replace('\n', '')
        
        try:
            file = open(path, 'w')
            
        except IOError:
            tkMessageBox.showerror('Write to File', 'The specified could not be opened. Check path/permissions.')
            return
        
        file.write(self.data.toString())
        file.close()
        tkMessageBox.showinfo('Write to FIle', 'Export has been written to file.')
        